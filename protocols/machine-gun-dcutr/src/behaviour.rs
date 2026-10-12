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
    num::NonZeroUsize,
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
    /// The relayed connection that the hole-punch tried to upgrade.
    pub relayed_connection_id: ConnectionId,
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
    #[error("Relayed connection closed before the hole-punch finished")]
    RelayedConnectionClosed,
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

    /// Hole-punch attempts in progress, keyed by the relayed connection they upgrade.
    attempts: HashMap<ConnectionId, Attempt>,

    /// Configuration parameters.
    config: Config,
}

/// Hole-punching on one relayed connection. Each CONNECT round is one attempt, which has
/// failed only once its burst has fired every dial and all of them have failed.
struct Attempt {
    peer: PeerId,
    /// Number of CONNECT rounds negotiated on the relayed connection so far.
    number: u8,
    /// Whether we are the listener on the relayed connection and thus drive the retries.
    locally_initiated: bool,
    /// Direct dials that have neither failed nor succeeded yet.
    outstanding: HashSet<ConnectionId>,
    burst: Option<PendingBurst>,
    /// Whether the relayed connection has closed. The attempt then ends with its current round,
    /// so this is only set while dials are outstanding or a burst is pending.
    relayed_closed: bool,
}

/// The QUIC dials of an attempt that have not been fired yet.
struct PendingBurst {
    delay: Pin<Box<Delay>>,
    remaining: NonZeroUsize,
    addresses: Vec<Multiaddr>,
}

impl Attempt {
    fn new(peer: PeerId, locally_initiated: bool) -> Self {
        Self {
            peer,
            number: 0,
            locally_initiated,
            outstanding: HashSet::new(),
            burst: None,
            relayed_closed: false,
        }
    }

    fn dial(&mut self, addresses: Vec<Multiaddr>) -> DialOpts {
        let mut builder = DialOpts::peer_id(self.peer)
            .condition(dial_opts::PeerCondition::Always)
            .addresses(addresses);

        if self.locally_initiated {
            builder = builder.override_role();
        }

        let opts = builder.build();
        self.outstanding.insert(opts.connection_id());
        opts
    }
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
            attempts: Default::default(),
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

    /// The hole-punch address candidates advertised to remote peers, each ending in
    /// `/p2p/<local_peer_id>`.
    ///
    /// A relayed connection captures the candidates when it is established, so changes
    /// only apply to relayed connections established afterwards.
    pub fn address_candidates(&self) -> &[Multiaddr] {
        &self.address_candidates
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

    /// Start the next round of the attempt on `relayed_connection_id`.
    ///
    /// TCP addresses get a single dial, because concurrent TCP dials to the same remote from
    /// the same source port hit the 4-tuple constraint and fall back to ephemeral ports. QUIC
    /// addresses get a burst of dials that all share the same UDP socket.
    fn start_round(
        &mut self,
        peer: PeerId,
        relayed_connection_id: ConnectionId,
        locally_initiated: bool,
        addresses: Vec<Multiaddr>,
    ) {
        tracing::debug!(
            target = %peer,
            relayed_connection = %relayed_connection_id,
            ?addresses,
            "Initiating hole punching"
        );

        let attempt = self
            .attempts
            .entry(relayed_connection_id)
            .or_insert_with(|| Attempt::new(peer, locally_initiated));
        attempt.number = attempt.number.saturating_add(1);

        let (quic_addrs, tcp_addrs): (Vec<_>, Vec<_>) = addresses.into_iter().partition(is_quic);

        if !tcp_addrs.is_empty() {
            let opts = attempt.dial(tcp_addrs);
            self.queued_events.push_back(ToSwarm::Dial { opts });
        }

        attempt.burst = None;
        if !quic_addrs.is_empty() {
            tracing::debug!(
                target = %peer,
                count = quic_addrs.len(),
                burst_count = self.config.hole_punch_burst_count,
                interval_ms = self.config.hole_punch_burst_interval.as_millis(),
                "Hole-punch burst for QUIC addresses"
            );

            let opts = attempt.dial(quic_addrs.clone());
            self.queued_events.push_back(ToSwarm::Dial { opts });

            attempt.burst =
                NonZeroUsize::new(self.config.hole_punch_burst_count - 1).map(|remaining| {
                    PendingBurst {
                        delay: Box::pin(Delay::new(self.config.hole_punch_burst_interval)),
                        remaining,
                        addresses: quic_addrs,
                    }
                });
        }
    }

    /// The relayed connection whose attempt made the direct dial `connection_id`.
    fn attempt_dialing(&self, connection_id: ConnectionId) -> Option<ConnectionId> {
        self.attempts
            .iter()
            .find(|(_, attempt)| attempt.outstanding.contains(&connection_id))
            .map(|(relayed_connection_id, _)| *relayed_connection_id)
    }

    fn on_dial_failure(&mut self, DialFailure { connection_id, .. }: DialFailure) {
        let Some(relayed_connection_id) = self.attempt_dialing(connection_id) else {
            return;
        };
        let attempt = self
            .attempts
            .get_mut(&relayed_connection_id)
            .expect("attempt to exist for its own dial");
        attempt.outstanding.remove(&connection_id);

        if !attempt.outstanding.is_empty() || attempt.burst.is_some() {
            return;
        }

        let error = if attempt.number >= MAX_NUMBER_OF_UPGRADE_ATTEMPTS {
            InnerError::AttemptsExceeded(MAX_NUMBER_OF_UPGRADE_ATTEMPTS)
        } else if attempt.relayed_closed {
            InnerError::RelayedConnectionClosed
        } else {
            // The remote drives the retries if we are the dialer on the relayed connection.
            if attempt.locally_initiated {
                self.queued_events.push_back(ToSwarm::NotifyHandler {
                    handler: NotifyHandler::One(relayed_connection_id),
                    peer_id: attempt.peer,
                    event: Either::Left(handler::relayed::Command::Connect),
                });
            }
            return;
        };
        self.fail_attempt(relayed_connection_id, error);
    }

    fn fail_attempt(&mut self, relayed_connection_id: ConnectionId, error: InnerError) {
        let attempt = self
            .attempts
            .remove(&relayed_connection_id)
            .expect("attempt to exist");
        self.queued_events.push_back(ToSwarm::GenerateEvent(Event {
            remote_peer_id: attempt.peer,
            relayed_connection_id,
            result: Err(Error { inner: error }),
        }));
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
        if connected_point.is_relayed() {
            if let Some(attempt) = self.attempts.get_mut(&connection_id) {
                if attempt.outstanding.is_empty() && attempt.burst.is_none() {
                    self.fail_attempt(connection_id, InnerError::RelayedConnectionClosed);
                } else {
                    attempt.relayed_closed = true;
                }
            }
            return;
        }

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

        // The remote's dial won the race. We cannot tell which relayed connection's round it
        // belongs to, so it completes every attempt with this peer.
        let completed = self.attempts.extract_if(|_, attempt| attempt.peer == peer);
        self.queued_events
            .extend(completed.map(|(relayed_connection_id, _)| {
                ToSwarm::GenerateEvent(Event {
                    remote_peer_id: peer,
                    relayed_connection_id,
                    result: Ok(connection_id),
                })
            }));

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

        if let Some(relayed_connection_id) = self.attempt_dialing(connection_id) {
            self.attempts.remove(&relayed_connection_id);
            self.queued_events.push_back(ToSwarm::GenerateEvent(Event {
                remote_peer_id: peer,
                relayed_connection_id,
                result: Ok(connection_id),
            }));
        }
        Ok(Either::Right(dummy::ConnectionHandler))
    }

    fn on_connection_handler_event(
        &mut self,
        event_source: PeerId,
        connection_id: ConnectionId,
        handler_event: THandlerOutEvent<Self>,
    ) {
        let handler_event = match handler_event {
            Either::Left(handler_event) => handler_event,
            // TODO: remove when Rust 1.82 is MSRV
            #[allow(unreachable_patterns)]
            Either::Right(never) => libp2p_core::util::unreachable(never),
        };

        match handler_event {
            handler::relayed::Event::InboundConnectNegotiated { remote_addrs } => {
                tracing::debug!(target=%event_source, addresses=?remote_addrs, "Attempting to hole-punch as dialer");
                self.start_round(event_source, connection_id, false, remote_addrs);
            }
            handler::relayed::Event::OutboundConnectNegotiated { remote_addrs } => {
                tracing::debug!(target=%event_source, addresses=?remote_addrs, "Attempting to hole-punch as listener");
                self.start_round(event_source, connection_id, true, remote_addrs);
            }
            handler::relayed::Event::InboundConnectFailed { error } => {
                self.attempts.remove(&connection_id);
                self.queued_events.push_back(ToSwarm::GenerateEvent(Event {
                    remote_peer_id: event_source,
                    relayed_connection_id: connection_id,
                    result: Err(Error {
                        inner: InnerError::InboundError(error),
                    }),
                }));
            }
            handler::relayed::Event::OutboundConnectFailed { error } => {
                self.attempts.remove(&connection_id);
                self.queued_events.push_back(ToSwarm::GenerateEvent(Event {
                    remote_peer_id: event_source,
                    relayed_connection_id: connection_id,
                    result: Err(Error {
                        inner: InnerError::OutboundError(error),
                    }),
                }));
            }
        };
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.queued_events.pop_front() {
            return Poll::Ready(event);
        }

        let burst_interval = self.config.hole_punch_burst_interval;
        for (relayed_connection_id, attempt) in self.attempts.iter_mut() {
            let Some(burst) = attempt.burst.as_mut() else {
                continue;
            };
            if burst.delay.as_mut().poll(cx).is_pending() {
                continue;
            }

            let addresses = burst.addresses.clone();
            let remaining = burst.remaining.get() - 1;
            match NonZeroUsize::new(remaining) {
                Some(remaining) => {
                    burst.remaining = remaining;
                    burst.delay = Box::pin(Delay::new(burst_interval));
                }
                None => attempt.burst = None,
            }

            tracing::debug!(
                peer = %attempt.peer,
                relayed_connection = %relayed_connection_id,
                remaining,
                "Firing burst dial"
            );
            let opts = attempt.dial(addresses);
            return Poll::Ready(ToSwarm::Dial { opts });
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
    use std::{collections::HashSet, iter, thread};

    use futures::{executor::block_on, future::poll_fn, task::noop_waker_ref};
    use libp2p_core::multiaddr::Protocol;
    use libp2p_swarm::DialError;

    use super::*;

    const BURST: usize = 4;

    type Action = ToSwarm<Event, THandlerInEvent<Behaviour>>;

    fn peer_id() -> PeerId {
        PeerId::random()
    }

    fn memory_addr(port: u64) -> Multiaddr {
        Multiaddr::empty().with(Protocol::Memory(port))
    }

    fn tcp_addr() -> Multiaddr {
        "/ip4/192.0.2.1/tcp/4001".parse().unwrap()
    }

    fn quic_addr() -> Multiaddr {
        "/ip4/192.0.2.1/udp/4001/quic-v1".parse().unwrap()
    }

    fn hole_punching_behaviour() -> Behaviour {
        Behaviour::with_config(
            peer_id(),
            Config::default()
                .with_hole_punch_burst_count(BURST)
                .with_hole_punch_burst_interval(Duration::from_millis(1)),
        )
    }

    fn negotiate(
        behaviour: &mut Behaviour,
        peer: PeerId,
        relayed: ConnectionId,
        locally_initiated: bool,
        remote_addrs: Vec<Multiaddr>,
    ) {
        let event = if locally_initiated {
            handler::relayed::Event::OutboundConnectNegotiated { remote_addrs }
        } else {
            handler::relayed::Event::InboundConnectNegotiated { remote_addrs }
        };
        behaviour.on_connection_handler_event(peer, relayed, Either::Left(event));
    }

    fn next(behaviour: &mut Behaviour) -> Action {
        block_on(poll_fn(|cx| behaviour.poll(cx)))
    }

    fn ready(behaviour: &mut Behaviour) -> Action {
        match behaviour.poll(&mut Context::from_waker(noop_waker_ref())) {
            Poll::Ready(action) => action,
            Poll::Pending => panic!("expected a queued action"),
        }
    }

    /// Polls once after the burst interval has passed, so a burst that is still pending fires.
    fn poll_idle(behaviour: &mut Behaviour) -> Option<Action> {
        thread::sleep(Duration::from_millis(20));
        match behaviour.poll(&mut Context::from_waker(noop_waker_ref())) {
            Poll::Ready(action) => Some(action),
            Poll::Pending => None,
        }
    }

    fn dials(behaviour: &mut Behaviour, count: usize) -> Vec<ConnectionId> {
        (0..count)
            .map(|_| match next(behaviour) {
                ToSwarm::Dial { opts } => opts.connection_id(),
                other => panic!("expected a dial, got {other:?}"),
            })
            .collect()
    }

    fn fail(behaviour: &mut Behaviour, connection_id: ConnectionId) {
        behaviour.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: None,
            error: &DialError::Aborted,
            connection_id,
        }));
    }

    fn event(action: Action) -> Event {
        match action {
            ToSwarm::GenerateEvent(event) => event,
            other => panic!("expected an event, got {other:?}"),
        }
    }

    fn assert_connect(action: Action, relayed: ConnectionId) {
        match action {
            ToSwarm::NotifyHandler {
                handler: NotifyHandler::One(id),
                event: Either::Left(handler::relayed::Command::Connect),
                ..
            } if id == relayed => {}
            other => panic!("expected a connect on {relayed}, got {other:?}"),
        }
    }

    #[test]
    fn failed_burst_queues_one_connect_on_listener() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed = ConnectionId::new_unchecked(1);

        negotiate(
            &mut behaviour,
            peer,
            relayed,
            true,
            vec![tcp_addr(), quic_addr()],
        );
        for _ in 0..1 + BURST {
            let dial = dials(&mut behaviour, 1)[0];
            fail(&mut behaviour, dial);
        }

        assert_connect(next(&mut behaviour), relayed);
        assert!(poll_idle(&mut behaviour).is_none());
    }

    #[test]
    fn failed_bursts_emit_one_error_on_dialer_at_max() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed = ConnectionId::new_unchecked(1);
        let mut late = None;

        for round in 1..=MAX_NUMBER_OF_UPGRADE_ATTEMPTS {
            negotiate(&mut behaviour, peer, relayed, false, vec![quic_addr()]);
            let mut round_dials = dials(&mut behaviour, BURST);
            if round == 1 {
                late = round_dials.pop();
            }
            for dial in round_dials {
                fail(&mut behaviour, dial);
            }
            assert!(poll_idle(&mut behaviour).is_none());
        }

        let late = late.unwrap();
        fail(&mut behaviour, late);
        let event = event(next(&mut behaviour));
        assert_eq!(event.remote_peer_id, peer);
        assert_eq!(event.relayed_connection_id, relayed);
        assert!(matches!(
            event.result,
            Err(Error {
                inner: InnerError::AttemptsExceeded(MAX_NUMBER_OF_UPGRADE_ATTEMPTS)
            })
        ));

        fail(&mut behaviour, late);
        assert!(poll_idle(&mut behaviour).is_none());
    }

    #[test]
    fn outbound_success_reports_once_and_cancels_burst() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed = ConnectionId::new_unchecked(1);

        negotiate(&mut behaviour, peer, relayed, true, vec![quic_addr()]);
        let burst_dials = dials(&mut behaviour, 2);
        behaviour
            .handle_established_outbound_connection(
                burst_dials[0],
                peer,
                &quic_addr(),
                Endpoint::Listener,
                PortUse::Reuse,
            )
            .unwrap();

        let event = event(next(&mut behaviour));
        assert_eq!(event.relayed_connection_id, relayed);
        assert_eq!(event.result.unwrap(), burst_dials[0]);

        fail(&mut behaviour, burst_dials[1]);
        assert!(poll_idle(&mut behaviour).is_none());
    }

    #[test]
    fn inbound_success_reports_once_and_cancels_burst() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed = ConnectionId::new_unchecked(1);
        let direct = ConnectionId::new_unchecked(2);

        negotiate(&mut behaviour, peer, relayed, false, vec![quic_addr()]);
        let burst_dials = dials(&mut behaviour, 2);
        behaviour
            .handle_established_inbound_connection(direct, peer, &tcp_addr(), &tcp_addr())
            .unwrap();

        let event = event(next(&mut behaviour));
        assert_eq!(event.relayed_connection_id, relayed);
        assert_eq!(event.result.unwrap(), direct);

        for dial in burst_dials {
            fail(&mut behaviour, dial);
        }
        assert!(poll_idle(&mut behaviour).is_none());
    }

    #[test]
    fn finishing_one_relayed_connection_keeps_the_others_burst() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed_1 = ConnectionId::new_unchecked(1);
        let relayed_2 = ConnectionId::new_unchecked(2);

        negotiate(&mut behaviour, peer, relayed_1, true, vec![quic_addr()]);
        negotiate(&mut behaviour, peer, relayed_2, true, vec![quic_addr()]);
        let first_dials = dials(&mut behaviour, 2);
        behaviour
            .handle_established_outbound_connection(
                first_dials[0],
                peer,
                &quic_addr(),
                Endpoint::Listener,
                PortUse::Reuse,
            )
            .unwrap();
        assert_eq!(event(next(&mut behaviour)).relayed_connection_id, relayed_1);

        let rest = dials(&mut behaviour, BURST - 1);
        for dial in iter::once(first_dials[1]).chain(rest) {
            fail(&mut behaviour, dial);
        }

        assert_connect(next(&mut behaviour), relayed_2);
        assert!(poll_idle(&mut behaviour).is_none());
    }

    #[test]
    fn inbound_success_completes_every_attempt_with_the_peer() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed_1 = ConnectionId::new_unchecked(1);
        let relayed_2 = ConnectionId::new_unchecked(2);
        let direct = ConnectionId::new_unchecked(3);

        negotiate(&mut behaviour, peer, relayed_1, true, vec![quic_addr()]);
        negotiate(&mut behaviour, peer, relayed_2, true, vec![quic_addr()]);
        dials(&mut behaviour, 2);
        behaviour
            .handle_established_inbound_connection(direct, peer, &tcp_addr(), &tcp_addr())
            .unwrap();

        let completed = (0..2)
            .map(|_| event(next(&mut behaviour)).relayed_connection_id)
            .collect::<HashSet<_>>();
        assert_eq!(completed, HashSet::from([relayed_1, relayed_2]));
        assert!(poll_idle(&mut behaviour).is_none());
    }

    #[test]
    fn handshake_failure_ends_the_attempt() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed = ConnectionId::new_unchecked(1);

        negotiate(&mut behaviour, peer, relayed, true, vec![quic_addr()]);
        let first_dial = dials(&mut behaviour, 1)[0];
        behaviour.on_connection_handler_event(
            peer,
            relayed,
            Either::Left(handler::relayed::Event::OutboundConnectFailed {
                error: protocol::outbound::Error::Unsupported,
            }),
        );

        let event = event(next(&mut behaviour));
        assert_eq!(event.relayed_connection_id, relayed);
        assert!(event.result.is_err());

        fail(&mut behaviour, first_dial);
        assert!(poll_idle(&mut behaviour).is_none());
    }

    fn close_relayed(behaviour: &mut Behaviour, peer: PeerId, relayed: ConnectionId) {
        let relayed_addr: Multiaddr =
            format!("/ip4/192.0.2.2/tcp/4001/p2p/{}/p2p-circuit", peer_id())
                .parse()
                .unwrap();
        behaviour.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: relayed,
            endpoint: &ConnectedPoint::Listener {
                local_addr: relayed_addr,
                send_back_addr: tcp_addr(),
            },
            cause: None,
            remaining_established: 0,
        }));
    }

    fn assert_relayed_connection_closed(event: Event, relayed: ConnectionId) {
        assert_eq!(event.relayed_connection_id, relayed);
        assert!(matches!(
            event.result,
            Err(Error {
                inner: InnerError::RelayedConnectionClosed
            })
        ));
    }

    #[test]
    fn closing_the_relayed_connection_mid_round_still_reports_the_failure() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed = ConnectionId::new_unchecked(1);

        negotiate(&mut behaviour, peer, relayed, true, vec![quic_addr()]);
        let first_dial = dials(&mut behaviour, 1)[0];
        close_relayed(&mut behaviour, peer, relayed);

        let rest = (1..BURST)
            .map(|_| match poll_idle(&mut behaviour) {
                Some(ToSwarm::Dial { opts }) => opts.connection_id(),
                other => panic!("expected the burst to keep firing, got {other:?}"),
            })
            .collect::<Vec<_>>();
        for dial in iter::once(first_dial).chain(rest) {
            fail(&mut behaviour, dial);
        }

        assert_relayed_connection_closed(event(ready(&mut behaviour)), relayed);
        assert!(poll_idle(&mut behaviour).is_none());
    }

    #[test]
    fn closing_the_relayed_connection_mid_round_still_reports_success() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed = ConnectionId::new_unchecked(1);

        negotiate(&mut behaviour, peer, relayed, true, vec![quic_addr()]);
        let first_dial = dials(&mut behaviour, 1)[0];
        close_relayed(&mut behaviour, peer, relayed);
        behaviour
            .handle_established_outbound_connection(
                first_dial,
                peer,
                &quic_addr(),
                Endpoint::Listener,
                PortUse::Reuse,
            )
            .unwrap();

        let event = event(ready(&mut behaviour));
        assert_eq!(event.relayed_connection_id, relayed);
        assert_eq!(event.result.unwrap(), first_dial);
        assert!(poll_idle(&mut behaviour).is_none());
    }

    #[test]
    fn closing_the_relayed_connection_between_rounds_fails_at_once() {
        let mut behaviour = hole_punching_behaviour();
        let peer = peer_id();
        let relayed = ConnectionId::new_unchecked(1);

        negotiate(&mut behaviour, peer, relayed, true, vec![quic_addr()]);
        for dial in dials(&mut behaviour, BURST) {
            fail(&mut behaviour, dial);
        }
        assert_connect(next(&mut behaviour), relayed);

        close_relayed(&mut behaviour, peer, relayed);

        assert_relayed_connection_closed(event(ready(&mut behaviour)), relayed);
        assert!(poll_idle(&mut behaviour).is_none());
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
