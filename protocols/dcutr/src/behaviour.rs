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
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use either::Either;
use futures_timer::Delay;
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

const DEFAULT_HOLE_PUNCH_BURST_COUNT: usize = 5;
const DEFAULT_HOLE_PUNCH_BURST_INTERVAL: Duration = Duration::from_millis(20);

/// Configuration for the DCUtR [`Behaviour`].
///
/// Use the builder methods to customize hole-punching parameters.
#[derive(Debug, Clone)]
pub struct Config {
    /// Number of rapid-fire dials per QUIC hole-punch attempt.
    ///
    /// After the DCUtR CONNECT/SYNC handshake, this many dials are emitted in
    /// quick succession for QUIC addresses to increase the chance of at least one
    /// Initial packet arriving during the NAT mapping window. All dials share the
    /// same UDP socket (same source port) via quinn's endpoint multiplexing.
    ///
    /// TCP addresses always use a single dial (no burst) because concurrent dials
    /// from the same source port hit the TCP 4-tuple constraint and fall back to
    /// ephemeral ports, defeating hole-punching.
    ///
    /// Default: 5.
    hole_punch_burst_count: usize,

    /// Delay between rapid-fire QUIC dials within a burst.
    ///
    /// Should be a small fraction of the typical RTT (50–250 ms) so that
    /// multiple packets arrive during the NAT mapping window.
    ///
    /// Default: 20 ms.
    hole_punch_burst_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hole_punch_burst_count: DEFAULT_HOLE_PUNCH_BURST_COUNT,
            hole_punch_burst_interval: DEFAULT_HOLE_PUNCH_BURST_INTERVAL,
        }
    }
}

impl Config {
    /// Set the number of rapid-fire dials per QUIC hole-punch attempt.
    ///
    /// Set to 1 to disable burst dials. Only affects QUIC addresses.
    pub fn with_hole_punch_burst_count(mut self, count: usize) -> Self {
        self.hole_punch_burst_count = count.max(1);
        self
    }

    /// Set the delay between rapid-fire QUIC dials within a burst.
    ///
    /// Should be a small fraction of the expected RTT between peers.
    pub fn with_hole_punch_burst_interval(mut self, interval: Duration) -> Self {
        self.hole_punch_burst_interval = interval;
        self
    }
}

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

    direct_to_relayed_connections: HashMap<ConnectionId, ConnectionId>,

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

    /// Pending rapid-fire QUIC dial bursts.
    ///
    /// Each entry contains a timer, remaining burst count, the target peer,
    /// the addresses to dial, the relayed connection ID, and whether this is
    /// a locally-initiated (OutboundConnect) or remote-initiated (InboundConnect)
    /// hole-punch.
    pending_bursts: Vec<PendingBurst>,

    /// Configuration parameters.
    config: Config,
}

/// A pending rapid-fire burst of hole-punch dials.
struct PendingBurst {
    delay: Pin<Box<Delay>>,
    remaining: usize,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    relayed_connection_id: ConnectionId,
    override_role: bool,
}

impl Behaviour {
    /// Create a new DCUtR [`Behaviour`] with default configuration.
    pub fn new(local_peer_id: PeerId) -> Self {
        Self::with_config(local_peer_id, Config::default())
    }

    /// Create a new DCUtR [`Behaviour`] with custom configuration.
    pub fn with_config(local_peer_id: PeerId, config: Config) -> Self {
        Behaviour {
            queued_events: Default::default(),
            direct_connections: Default::default(),
            address_candidates: Vec::new(),
            me: local_peer_id,
            direct_to_relayed_connections: Default::default(),
            outgoing_direct_connection_attempts: Default::default(),
            holepunch_in_progress: Default::default(),
            pending_bursts: Vec::new(),
            config,
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

    /// Initiate hole-punch dials, with rapid-fire bursts for QUIC addresses.
    ///
    /// Splits the address list into QUIC and non-QUIC (TCP) addresses:
    /// - **QUIC addresses**: emits a burst of dials (configurable count and interval).
    ///   All dials share the same UDP socket via quinn's endpoint multiplexing,
    ///   creating a true "machine gun" of Initial packets from the same source port.
    /// - **TCP addresses**: emits a single dial. Concurrent TCP dials to the same
    ///   remote from the same source port hit the 4-tuple constraint and fall back
    ///   to ephemeral ports, defeating hole-punching.
    fn initiate_hole_punch_dials(
        &mut self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        relayed_connection_id: ConnectionId,
        locally_initiated: bool,
        override_role: bool,
    ) {
        let (quic_addrs, tcp_addrs): (Vec<_>, Vec<_>) =
            addresses.into_iter().partition(is_quic);

        // TCP addresses: single dial (no burst).
        if !tcp_addrs.is_empty() {
            tracing::debug!(
                target = %peer_id,
                count = tcp_addrs.len(),
                "Hole-punch dial for TCP addresses (single shot)"
            );
            let opts = self.create_hole_punch_dial(
                peer_id,
                tcp_addrs,
                relayed_connection_id,
                override_role,
            );
            self.queued_events.push_back(ToSwarm::Dial { opts });
        }

        // QUIC addresses: rapid-fire burst.
        if !quic_addrs.is_empty() {
            let burst_count = self.config.hole_punch_burst_count;
            let burst_interval = self.config.hole_punch_burst_interval;

            tracing::debug!(
                target = %peer_id,
                count = quic_addrs.len(),
                burst_count,
                interval_ms = burst_interval.as_millis(),
                "Hole-punch burst for QUIC addresses"
            );

            // Emit the first QUIC dial immediately.
            let opts = self.create_hole_punch_dial(
                peer_id,
                quic_addrs.clone(),
                relayed_connection_id,
                override_role,
            );
            self.queued_events.push_back(ToSwarm::Dial { opts });

            // Schedule remaining burst dials with delays.
            if burst_count > 1 {
                self.pending_bursts.push(PendingBurst {
                    delay: Box::pin(Delay::new(burst_interval)),
                    remaining: burst_count - 1,
                    peer_id,
                    addresses: quic_addrs,
                    relayed_connection_id,
                    override_role,
                });
            }
        }
    }

    /// Create a single hole-punch dial and register it in tracking state.
    fn create_hole_punch_dial(
        &mut self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        relayed_connection_id: ConnectionId,
        override_role: bool,
    ) -> DialOpts {
        let mut builder = DialOpts::peer_id(peer_id)
            .condition(dial_opts::PeerCondition::Always)
            .addresses(addresses);

        if override_role {
            builder = builder.override_role();
        }

        let opts = builder.build();
        let connection_id = opts.connection_id();

        self.direct_to_relayed_connections
            .insert(connection_id, relayed_connection_id);

        opts
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

        let Some(relayed_connection_id) = self
            .direct_to_relayed_connections
            .get(&failed_direct_connection)
        else {
            return;
        };

        let Some(attempt) = self
            .outgoing_direct_connection_attempts
            .get(&(*relayed_connection_id, peer_id))
        else {
            return;
        };

        if *attempt < MAX_NUMBER_OF_UPGRADE_ATTEMPTS {
            self.queued_events.push_back(ToSwarm::NotifyHandler {
                handler: NotifyHandler::One(*relayed_connection_id),
                peer_id,
                event: Either::Left(handler::relayed::Command::Connect),
            })
        } else {
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
        if let Some(&relayed_connection_id) =
            self.direct_to_relayed_connections.get(&connection_id)
        {
            // Clean up attempt tracking if still present.
            // With rapid-fire bursts, multiple dials may succeed — only the first
            // one emits an event (via holepunch_in_progress check below).
            self.outgoing_direct_connection_attempts
                .remove(&(relayed_connection_id, peer));

            // Only emit a success event for the first successful dial.
            // Subsequent burst dials that succeed are silently accepted
            // (the connection is still valid, just no duplicate event).
            if self.holepunch_in_progress.remove(&peer) {
                self.queued_events.extend([ToSwarm::GenerateEvent(Event {
                    remote_peer_id: peer,
                    result: Ok(connection_id),
                })]);
            }
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
                Some(relayed_connection_id) => *relayed_connection_id,
            },
        };

        match handler_event {
            Either::Left(handler::relayed::Event::InboundConnectNegotiated { remote_addrs }) => {
                tracing::debug!(target=%event_source, addresses=?remote_addrs, "Attempting to hole-punch as dialer");

                self.holepunch_in_progress.insert(event_source);
                *self
                    .outgoing_direct_connection_attempts
                    .entry((relayed_connection_id, event_source))
                    .or_default() += 1;
                self.initiate_hole_punch_dials(
                    event_source,
                    remote_addrs,
                    relayed_connection_id,
                    false,  // not locally initiated
                    false,  // no role override
                );
            }
            Either::Left(handler::relayed::Event::InboundConnectFailed { error }) => {
                self.queued_events.push_back(ToSwarm::GenerateEvent(Event {
                    remote_peer_id: event_source,
                    result: Err(Error {
                        inner: InnerError::InboundError(error),
                    }),
                }));
            }
            Either::Left(handler::relayed::Event::OutboundConnectFailed { error }) => {
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

                self.holepunch_in_progress.insert(event_source);
                *self
                    .outgoing_direct_connection_attempts
                    .entry((relayed_connection_id, event_source))
                    .or_default() += 1;
                self.initiate_hole_punch_dials(
                    event_source,
                    remote_addrs,
                    relayed_connection_id,
                    true,   // locally initiated
                    true,   // override role
                );
            }
            Either::Right(never) => libp2p_core::util::unreachable(never),
        };
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.queued_events.pop_front() {
            return Poll::Ready(event);
        }

        // Drive pending rapid-fire bursts.
        // Check if any burst timer has fired and emit the next dial.
        let mut i = 0;
        while i < self.pending_bursts.len() {
            if self.pending_bursts[i].remaining == 0 {
                self.pending_bursts.swap_remove(i);
                continue;
            }

            // If the hole-punch already succeeded for this peer, cancel remaining bursts.
            if !self.holepunch_in_progress.contains(&self.pending_bursts[i].peer_id) {
                tracing::debug!(
                    peer = %self.pending_bursts[i].peer_id,
                    remaining = self.pending_bursts[i].remaining,
                    "Cancelling remaining burst dials — hole-punch already completed"
                );
                self.pending_bursts.swap_remove(i);
                continue;
            }

            match self.pending_bursts[i].delay.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    let burst = &self.pending_bursts[i];
                    let peer_id = burst.peer_id;
                    let addresses = burst.addresses.clone();
                    let relayed_connection_id = burst.relayed_connection_id;
                    let override_role = burst.override_role;

                    self.pending_bursts[i].remaining -= 1;
                    let remaining = self.pending_bursts[i].remaining;

                    let opts = self.create_hole_punch_dial(
                        peer_id,
                        addresses,
                        relayed_connection_id,
                        override_role,
                    );

                    tracing::debug!(
                        peer = %peer_id,
                        remaining,
                        "Firing burst dial"
                    );

                    // Reset timer for next burst.
                    if remaining > 0 {
                        self.pending_bursts[i].delay = Box::pin(Delay::new(self.config.hole_punch_burst_interval));
                    }

                    return Poll::Ready(ToSwarm::Dial { opts });
                }
                Poll::Pending => {
                    i += 1;
                }
            }
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

fn is_quic(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|p| matches!(p, Protocol::QuicV1 | Protocol::Quic))
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
