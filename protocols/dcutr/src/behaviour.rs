// Copyright 2021 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! [`NetworkBehaviour`] to act as a direct connection upgrade through relay node.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    task::{Context, Poll},
};

use either::Either;
use libp2p_core::{
    connection::ConnectedPoint, multiaddr::Protocol, transport::PortUse, Endpoint, Multiaddr,
};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    behaviour::{ConnectionClosed, DialFailure, FromSwarm},
    dial_opts::{self, DialOpts},
    dummy, ConnectionDenied, ConnectionHandler, ConnectionId, NetworkBehaviour, NotifyHandler,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use thiserror::Error;

use crate::{handler, protocol};

pub(crate) const MAX_NUMBER_OF_UPGRADE_ATTEMPTS: u8 = 3;

/// The event produced by the DCUtR [`Behaviour`], delivered to the application via
/// [`SwarmEvent::Behaviour`](libp2p_swarm::SwarmEvent::Behaviour).
///
/// DCUtR (Direct Connection Upgrade through Relay) is a protocol that enables two peers
/// who are communicating via a relay to attempt a direct connection using hole-punching.
/// This event reports the outcome of such an attempt.
///
/// # Event Lifecycle
///
/// 1. When a relayed connection exists between two peers, the DCUtR behaviour automatically
///    initiates a hole-punching attempt to upgrade to a direct connection.
/// 2. The protocol coordinates a synchronized dial between both peers using the relayed
///    connection for signaling.
/// 3. **On success**: An `Event` is emitted with `result: Ok(connection_id)`, where
///    `connection_id` identifies the new direct connection. The relayed connection may
///    then be closed.
/// 4. **On failure**: An `Event` is emitted with `result: Err(error)`, indicating the
///    hole-punching attempt failed (e.g. both peers are behind symmetric NATs). The
///    relayed connection remains active.
///
/// # Recommended Action
///
/// - **On success**: No action required. The swarm will automatically use the new direct
///   connection. You may optionally close the relayed connection.
/// - **On failure**: The relayed connection continues to work. The application may retry
///   or accept the relayed path.
#[derive(Debug)]
pub struct Event {
    /// The peer with whom the direct connection upgrade was attempted.
    pub remote_peer_id: PeerId,
    /// The result of the hole-punching attempt. `Ok(connection_id)` contains the ID
    /// of the newly established direct connection. `Err(error)` indicates the attempt
    /// failed.
    pub result: Result<ConnectionId, Error>,
}

/// Error that occurred during a DCUtR hole-punching attempt.
///
/// This wraps an internal error type. The hole-punching may fail because the maximum
/// number of dial attempts was exceeded, or because of an error in the inbound or
/// outbound protocol negotiation.
#[derive(Debug, Error)]
#[error("Failed to hole-punch connection: {inner}")]
pub struct Error {
    inner: InnerError,
}

#[derive(Debug, Error)]
enum InnerError {
    #[error("Giving up after {0} dial attempts")]
    AttemptsExceeded(u8),
    #[error("Inbound stream error: {0}")]
    InboundError(protocol::inbound::Error),
    #[error("Outbound stream error: {0}")]
    OutboundError(protocol::outbound::Error),
}

pub struct Behaviour {
    /// Queue of actions to return when polled.
    queued_events: VecDeque<ToSwarm<Event, Either<handler::relayed::Command, Infallible>>>,

    /// All direct (non-relayed) connections.
    direct_connections: HashMap<PeerId, HashSet<ConnectionId>>,

    /// Hole-punch address candidates, managed explicitly by the application.
    ///
    /// The application adds addresses via [`Behaviour::add_address`] and removes
    /// them via [`Behaviour::remove_address`]. This gives the application full
    /// control over which addresses are advertised during hole-punching, allowing
    /// it to correlate addresses with relay connection lifecycles.
    address_candidates: Vec<Multiaddr>,

    /// The local peer ID, used to append `/p2p/<peer_id>` to candidate addresses.
    me: PeerId,

    /// Maps direct (hole-punch) connection IDs to their relayed connection ID and
    /// a flag indicating whether the local node initiated the DCUtR upgrade.
    ///
    /// `locally_initiated = true` means this node is the listener on the relay
    /// (OutboundConnect path) — local retries via `Command::Connect`.
    /// `locally_initiated = false` means this node is the dialer on the relay
    /// (InboundConnect path) — remote controls retries.
    direct_to_relayed_connections: HashMap<ConnectionId, (ConnectionId, bool)>,

    /// Indexed by the [`ConnectionId`] of the relayed connection and
    /// the [`PeerId`] we are trying to establish a direct connection to.
    outgoing_direct_connection_attempts: HashMap<(ConnectionId, PeerId), u8>,

    /// Peers for which a hole-punch dial is currently in progress.
    ///
    /// When the hole-punch succeeds, the direct connection may arrive as
    /// **inbound** on this node (if the remote's dial won the race). In that
    /// case, `handle_established_outbound_connection` never fires for our dial,
    /// so we use this set to detect hole-punch success in
    /// `handle_established_inbound_connection` as well.
    holepunch_in_progress: HashSet<PeerId>,
}

impl Behaviour {
    pub fn new(local_peer_id: PeerId) -> Self {
        Behaviour {
            queued_events: Default::default(),
            direct_connections: Default::default(),
            address_candidates: Vec::new(),
            me: local_peer_id,
            direct_to_relayed_connections: Default::default(),
            outgoing_direct_connection_attempts: Default::default(),
            holepunch_in_progress: Default::default(),
        }
    }

    /// Add an address candidate for hole-punching.
    ///
    /// The application should call this when it learns a valid external address,
    /// typically by correlating observed addresses from identify with active relay
    /// connections. Only addresses associated with live relay connections should be
    /// added, since their NAT mappings are known to be active.
    ///
    /// The address will have `/p2p/<local_peer_id>` appended if not already present.
    /// Relayed addresses (containing `/p2p-circuit`) are ignored.
    pub fn add_address(&mut self, mut address: Multiaddr) {
        if is_relayed(&address) {
            tracing::trace!(%address, "Ignoring relayed address candidate");
            return;
        }

        if address.iter().last() != Some(Protocol::P2p(self.me)) {
            address.push(Protocol::P2p(self.me));
        }

        if !self.address_candidates.contains(&address) {
            tracing::debug!(%address, "Adding hole-punch address candidate");
            self.address_candidates.push(address);
        }
    }

    /// Remove an address candidate for hole-punching.
    ///
    /// The application should call this when a relay connection closes or a
    /// reservation expires, so that stale addresses are no longer advertised
    /// during hole-punching.
    ///
    /// The address will have `/p2p/<local_peer_id>` appended if not already present
    /// before attempting removal.
    pub fn remove_address(&mut self, mut address: Multiaddr) {
        if address.iter().last() != Some(Protocol::P2p(self.me)) {
            address.push(Protocol::P2p(self.me));
        }

        if let Some(pos) = self.address_candidates.iter().position(|a| *a == address) {
            tracing::debug!(%address, "Removing hole-punch address candidate");
            self.address_candidates.swap_remove(pos);
        }
    }

    fn observed_addresses(&self) -> Vec<Multiaddr> {
        let addrs = self.address_candidates.clone();
        tracing::debug!(
            count = addrs.len(),
            addresses = ?addrs,
            "Collecting hole-punch candidate addresses"
        );
        addrs
    }

    fn on_dial_failure(
        &mut self,
        DialFailure {
            peer_id,
            connection_id: failed_direct_connection,
            ..
        }: DialFailure,
    ) {
        let Some(peer_id) = peer_id else {
            return;
        };

        let Some(&(relayed_connection_id, locally_initiated)) = self
            .direct_to_relayed_connections
            .get(&failed_direct_connection)
        else {
            return;
        };

        let Some(attempt) = self
            .outgoing_direct_connection_attempts
            .get(&(relayed_connection_id, peer_id))
        else {
            return;
        };

        if *attempt < MAX_NUMBER_OF_UPGRADE_ATTEMPTS {
            if locally_initiated {
                // OutboundConnect path: we control retries.
                self.queued_events.push_back(ToSwarm::NotifyHandler {
                    handler: NotifyHandler::One(relayed_connection_id),
                    peer_id,
                    event: Either::Left(handler::relayed::Command::Connect),
                })
            }
            // InboundConnect path: remote controls retries, nothing to do here.
        } else {
            self.holepunch_in_progress.remove(&peer_id);
            self.queued_events.extend([ToSwarm::GenerateEvent(Event {
                remote_peer_id: peer_id,
                result: Err(Error {
                    inner: InnerError::AttemptsExceeded(MAX_NUMBER_OF_UPGRADE_ATTEMPTS),
                }),
            })]);
        }
    }

    fn on_connection_closed(
        &mut self,
        ConnectionClosed {
            peer_id,
            connection_id,
            endpoint: connected_point,
            ..
        }: ConnectionClosed,
    ) {
        if !connected_point.is_relayed() {
            let connections = self
                .direct_connections
                .get_mut(&peer_id)
                .expect("Peer of direct connection to be tracked.");
            connections
                .remove(&connection_id)
                .then_some(())
                .expect("Direct connection to be tracked.");
            if connections.is_empty() {
                self.direct_connections.remove(&peer_id);
            }
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Either<handler::relayed::Handler, dummy::ConnectionHandler>;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if is_relayed(local_addr) {
            let connected_point = ConnectedPoint::Listener {
                local_addr: local_addr.clone(),
                send_back_addr: remote_addr.clone(),
            };
            let mut handler =
                handler::relayed::Handler::new(connected_point, self.observed_addresses());
            handler.on_behaviour_event(handler::relayed::Command::Connect);

            // TODO: We could make two `handler::relayed::Handler` here, one inbound one outbound.
            return Ok(Either::Left(handler));
        }
        self.direct_connections
            .entry(peer)
            .or_default()
            .insert(connection_id);

        assert!(
            !self
                .direct_to_relayed_connections
                .contains_key(&connection_id),
            "state mismatch"
        );

        // If a hole-punch is in progress with this peer and we received a direct
        // inbound connection, the remote's dial won the race. Emit a success event
        // so the application knows the hole-punch succeeded regardless of which
        // side's dial created the connection.
        if self.holepunch_in_progress.remove(&peer) {
            self.queued_events.extend([ToSwarm::GenerateEvent(Event {
                remote_peer_id: peer,
                result: Ok(connection_id),
            })]);
        }

        Ok(Either::Right(dummy::ConnectionHandler))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if is_relayed(addr) {
            return Ok(Either::Left(handler::relayed::Handler::new(
                ConnectedPoint::Dialer {
                    address: addr.clone(),
                    role_override,
                    port_use,
                },
                self.observed_addresses(),
            ))); // TODO: We could make two `handler::relayed::Handler` here, one inbound one
                 // outbound.
        }

        self.direct_connections
            .entry(peer)
            .or_default()
            .insert(connection_id);

        // Whether this is a connection requested by this behaviour.
        if let Some(&(relayed_connection_id, locally_initiated)) =
            self.direct_to_relayed_connections.get(&connection_id)
        {
            if locally_initiated {
                // OutboundConnect path: assert state consistency.
                assert!(
                    self.outgoing_direct_connection_attempts
                        .remove(&(relayed_connection_id, peer))
                        .is_some(),
                    "state mismatch"
                );
            } else {
                // InboundConnect path: clean up attempt tracking.
                self.outgoing_direct_connection_attempts
                    .remove(&(relayed_connection_id, peer));
            }

            // Our outbound dial succeeded. Clean up the tracking so that an
            // inbound connection from the same peer (if both dials succeeded)
            // doesn't emit a duplicate event.
            self.holepunch_in_progress.remove(&peer);

            self.queued_events.extend([ToSwarm::GenerateEvent(Event {
                remote_peer_id: peer,
                result: Ok(connection_id),
            })]);
        }
        Ok(Either::Right(dummy::ConnectionHandler))
    }

    fn on_connection_handler_event(
        &mut self,
        event_source: PeerId,
        connection_id: ConnectionId,
        handler_event: THandlerOutEvent<Self>,
    ) {
        let relayed_connection_id = match handler_event.as_ref() {
            Either::Left(_) => connection_id,
            Either::Right(_) => match self.direct_to_relayed_connections.get(&connection_id) {
                None => {
                    // If the connection ID is unknown to us, it means we didn't create it so ignore
                    // any event coming from it.
                    return;
                }
                Some(&(relayed_connection_id, _)) => relayed_connection_id,
            },
        };

        match handler_event {
            Either::Left(handler::relayed::Event::InboundConnectNegotiated { remote_addrs }) => {
                tracing::debug!(target=%event_source, addresses=?remote_addrs, "Attempting to hole-punch as dialer");

                let opts = DialOpts::peer_id(event_source)
                    .addresses(remote_addrs)
                    .condition(dial_opts::PeerCondition::Always)
                    .build();

                let maybe_direct_connection_id = opts.connection_id();

                self.direct_to_relayed_connections
                    .insert(maybe_direct_connection_id, (relayed_connection_id, false));
                self.holepunch_in_progress.insert(event_source);
                *self
                    .outgoing_direct_connection_attempts
                    .entry((relayed_connection_id, event_source))
                    .or_default() += 1;
                self.queued_events.push_back(ToSwarm::Dial { opts });
            }
            Either::Left(handler::relayed::Event::InboundConnectFailed { error }) => {
                self.holepunch_in_progress.remove(&event_source);
                self.queued_events.push_back(ToSwarm::GenerateEvent(Event {
                    remote_peer_id: event_source,
                    result: Err(Error {
                        inner: InnerError::InboundError(error),
                    }),
                }));
            }
            Either::Left(handler::relayed::Event::OutboundConnectFailed { error }) => {
                self.holepunch_in_progress.remove(&event_source);
                self.queued_events.push_back(ToSwarm::GenerateEvent(Event {
                    remote_peer_id: event_source,
                    result: Err(Error {
                        inner: InnerError::OutboundError(error),
                    }),
                }));

                // Maybe treat these as transient and retry?
            }
            Either::Left(handler::relayed::Event::OutboundConnectNegotiated { remote_addrs }) => {
                tracing::debug!(target=%event_source, addresses=?remote_addrs, "Attempting to hole-punch as listener");

                let opts = DialOpts::peer_id(event_source)
                    .condition(dial_opts::PeerCondition::Always)
                    .addresses(remote_addrs)
                    .override_role()
                    .build();

                let maybe_direct_connection_id = opts.connection_id();

                self.direct_to_relayed_connections
                    .insert(maybe_direct_connection_id, (relayed_connection_id, true));
                self.holepunch_in_progress.insert(event_source);
                *self
                    .outgoing_direct_connection_attempts
                    .entry((relayed_connection_id, event_source))
                    .or_default() += 1;
                self.queued_events.push_back(ToSwarm::Dial { opts });
            }
            // TODO: remove when Rust 1.82 is MSRV
            #[allow(unreachable_patterns)]
            Either::Right(never) => libp2p_core::util::unreachable(never),
        };
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self))]
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.queued_events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(connection_closed) => {
                self.on_connection_closed(connection_closed)
            }
            FromSwarm::DialFailure(dial_failure) => self.on_dial_failure(dial_failure),
            _ => {}
        }
    }
}

fn is_relayed(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| p == Protocol::P2pCircuit)
}

#[cfg(test)]
mod tests {
    use libp2p_core::multiaddr::Protocol;

    use super::*;

    fn peer_id() -> PeerId {
        PeerId::random()
    }

    fn memory_addr(port: u64) -> Multiaddr {
        Multiaddr::empty().with(Protocol::Memory(port))
    }

    #[test]
    fn add_address_appends_p2p() {
        let me = peer_id();
        let mut behaviour = Behaviour::new(me);

        let addr = memory_addr(1000);
        behaviour.add_address(addr.clone());

        let addrs = behaviour.observed_addresses();
        assert_eq!(addrs.len(), 1);
        let mut expected = addr;
        expected.push(Protocol::P2p(me));
        assert_eq!(addrs[0], expected);
    }

    #[test]
    fn add_address_deduplicates() {
        let me = peer_id();
        let mut behaviour = Behaviour::new(me);

        let addr = memory_addr(1000);
        behaviour.add_address(addr.clone());
        behaviour.add_address(addr.clone());

        assert_eq!(behaviour.observed_addresses().len(), 1);
    }

    #[test]
    fn remove_address_works() {
        let me = peer_id();
        let mut behaviour = Behaviour::new(me);

        let addr1 = memory_addr(1000);
        let addr2 = memory_addr(2000);
        behaviour.add_address(addr1.clone());
        behaviour.add_address(addr2.clone());
        assert_eq!(behaviour.observed_addresses().len(), 2);

        behaviour.remove_address(addr1);

        let remaining = behaviour.observed_addresses();
        assert_eq!(remaining.len(), 1);
        let mut expected_addr2 = addr2;
        expected_addr2.push(Protocol::P2p(me));
        assert_eq!(remaining[0], expected_addr2);
    }

    #[test]
    fn relayed_addresses_are_not_stored() {
        let me = peer_id();
        let mut behaviour = Behaviour::new(me);

        let relayed = Multiaddr::empty()
            .with(Protocol::Memory(1000))
            .with(Protocol::P2p(PeerId::random()))
            .with(Protocol::P2pCircuit);

        behaviour.add_address(relayed);
        assert!(behaviour.observed_addresses().is_empty());
    }

    #[test]
    fn empty_behaviour_returns_no_addresses() {
        let me = peer_id();
        let behaviour = Behaviour::new(me);
        assert!(behaviour.observed_addresses().is_empty());
    }
}
