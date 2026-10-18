use core::fmt;
use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use futures::{StreamExt, channel::mpsc};
use libp2p_core::{Endpoint, Multiaddr, multiaddr::Protocol, transport::PortUse};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    self as swarm, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm, dial_opts::DialOpts,
};
use swarm::{
    ConnectionClosed, DialError, DialFailure, behaviour::ConnectionEstablished,
    dial_opts::PeerCondition,
};

use crate::{Control, handler::Handler, shared::Shared};

/// A generic behaviour for stream-oriented protocols.
pub struct Behaviour {
    shared: Arc<Mutex<Shared>>,
    dial_receiver: mpsc::Receiver<PeerId>,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self::new()
    }
}

impl Behaviour {
    pub fn new() -> Self {
        Self::with_config(Config::default())
    }

    /// Creates a [`Behaviour`] with the given [`Config`].
    pub fn with_config(config: Config) -> Self {
        let (dial_sender, dial_receiver) = mpsc::channel(0);

        Self {
            shared: Arc::new(Mutex::new(Shared::new(dial_sender, config))),
            dial_receiver,
        }
    }

    /// Obtain a new [`Control`].
    pub fn new_control(&self) -> Control {
        Control::new(self.shared.clone())
    }

    fn new_handler(&self, peer: PeerId, connection_id: ConnectionId, relayed: bool) -> Handler {
        let mut shared = Shared::lock(&self.shared);
        let receiver = shared.receiver(peer, connection_id, relayed);

        Handler::new(
            peer,
            self.shared.clone(),
            receiver,
            shared.is_eligible(relayed),
        )
    }
}

/// The configuration for a [`Behaviour`].
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub(crate) relayed_connections: bool,
    pub(crate) dialing: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            relayed_connections: true,
            dialing: true,
        }
    }
}

impl Config {
    /// Sets whether streams may use relayed connections.
    ///
    /// Defaults to `true`. With `false`, [`Control::open_stream`] only opens streams on direct
    /// connections, and relayed connections don't offer the protocols registered through
    /// [`Control::accept`].
    pub fn with_relayed_connections(mut self, enabled: bool) -> Self {
        self.relayed_connections = enabled;
        self
    }

    /// Sets whether [`Control::open_stream`] dials a peer it has no eligible connection to.
    ///
    /// Defaults to `true`. With `false`, [`Control::open_stream`] fails with
    /// [`std::io::ErrorKind::NotConnected`] instead.
    pub fn with_dialing(mut self, enabled: bool) -> Self {
        self.dialing = enabled;
        self
    }
}

fn is_relayed(address: &Multiaddr) -> bool {
    address.iter().any(|p| p == Protocol::P2pCircuit)
}

/// The protocol is already registered.
#[derive(Debug)]
pub struct AlreadyRegistered;

impl fmt::Display for AlreadyRegistered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The protocol is already registered")
    }
}

impl std::error::Error for AlreadyRegistered {}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = ();

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.new_handler(peer, connection_id, is_relayed(local_addr)))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.new_handler(peer, connection_id, is_relayed(addr)))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            }) => Shared::lock(&self.shared).on_connection_established(
                connection_id,
                peer_id,
                endpoint.is_relayed(),
            ),
            FromSwarm::ConnectionClosed(ConnectionClosed { connection_id, .. }) => {
                Shared::lock(&self.shared).on_connection_closed(connection_id)
            }
            FromSwarm::DialFailure(DialFailure {
                peer_id: Some(peer_id),
                error:
                    error @ (DialError::Transport(_)
                    | DialError::Denied { .. }
                    | DialError::NoAddresses
                    | DialError::WrongPeerId { .. }),
                ..
            }) => {
                let reason = error.to_string(); // We can only forward the string repr but it is better than nothing.

                Shared::lock(&self.shared).on_dial_failure(peer_id, reason)
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        libp2p_core::util::unreachable(event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Poll::Ready(Some(peer)) = self.dial_receiver.poll_next_unpin(cx) {
            return Poll::Ready(ToSwarm::Dial {
                opts: DialOpts::peer_id(peer)
                    .condition(PeerCondition::DisconnectedAndNotDialing)
                    .build(),
            });
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use futures::{FutureExt as _, task::noop_waker_ref};
    use libp2p_core::UpgradeInfo as _;
    use libp2p_swarm::{ConnectionHandler as _, StreamProtocol};

    use super::*;

    const PROTOCOL: StreamProtocol = StreamProtocol::new("/test");

    fn direct_addr() -> Multiaddr {
        Multiaddr::empty().with(Protocol::Memory(1))
    }

    fn relayed_addr() -> Multiaddr {
        direct_addr()
            .with(Protocol::P2p(PeerId::random()))
            .with(Protocol::P2pCircuit)
    }

    fn offered_inbound(handler: Handler) -> Vec<StreamProtocol> {
        handler
            .listen_protocol()
            .upgrade()
            .protocol_info()
            .collect()
    }

    fn offered_on_inbound(
        behaviour: &mut Behaviour,
        local_addr: &Multiaddr,
    ) -> Vec<StreamProtocol> {
        let handler = behaviour
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(0),
                PeerId::random(),
                local_addr,
                &Protocol::P2p(PeerId::random()).into(),
            )
            .unwrap();

        offered_inbound(handler)
    }

    fn offered_on_outbound(behaviour: &mut Behaviour, addr: &Multiaddr) -> Vec<StreamProtocol> {
        let handler = behaviour
            .handle_established_outbound_connection(
                ConnectionId::new_unchecked(0),
                PeerId::random(),
                addr,
                Endpoint::Dialer,
                PortUse::Reuse,
            )
            .unwrap();

        offered_inbound(handler)
    }

    #[test]
    fn relayed_connections_offer_no_protocols_when_disallowed() {
        let mut behaviour =
            Behaviour::with_config(Config::default().with_relayed_connections(false));
        let _incoming = behaviour.new_control().accept(PROTOCOL).unwrap();

        assert!(offered_on_inbound(&mut behaviour, &relayed_addr()).is_empty());
        assert!(offered_on_outbound(&mut behaviour, &relayed_addr()).is_empty());
        assert_eq!(
            offered_on_inbound(&mut behaviour, &direct_addr()),
            [PROTOCOL]
        );
        assert_eq!(
            offered_on_outbound(&mut behaviour, &direct_addr()),
            [PROTOCOL]
        );
    }

    #[test]
    fn relayed_connections_offer_protocols_by_default() {
        let mut behaviour = Behaviour::new();
        let _incoming = behaviour.new_control().accept(PROTOCOL).unwrap();

        assert_eq!(
            offered_on_inbound(&mut behaviour, &relayed_addr()),
            [PROTOCOL]
        );
        assert_eq!(
            offered_on_outbound(&mut behaviour, &relayed_addr()),
            [PROTOCOL]
        );
    }

    /// Opens a stream to an unconnected peer and returns whether the behaviour then dials.
    fn dials_on_open_stream(config: Config) -> bool {
        let mut behaviour = Behaviour::with_config(config);
        let _ = behaviour
            .new_control()
            .open_stream(PeerId::random(), PROTOCOL)
            .now_or_never();

        let mut cx = Context::from_waker(noop_waker_ref());
        matches!(behaviour.poll(&mut cx), Poll::Ready(ToSwarm::Dial { .. }))
    }

    #[test]
    fn open_stream_without_dialing_does_not_dial() {
        assert!(!dials_on_open_stream(Config::default().with_dialing(false)));
        assert!(dials_on_open_stream(Config::default()));
    }
}
