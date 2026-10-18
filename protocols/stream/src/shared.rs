use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    sync::{Arc, Mutex, MutexGuard},
};

use futures::channel::mpsc;
use libp2p_identity::PeerId;
use libp2p_swarm::{ConnectionId, Stream, StreamProtocol};
use rand::seq::IteratorRandom as _;

use crate::{AlreadyRegistered, Config, IncomingStreams, handler::NewStream};

pub(crate) struct Shared {
    /// Tracks the supported inbound protocols created via
    /// [`Control::accept`](crate::Control::accept).
    ///
    /// For each [`StreamProtocol`], we hold the [`mpsc::Sender`] corresponding to the
    /// [`mpsc::Receiver`] in [`IncomingStreams`].
    supported_inbound_protocols: HashMap<StreamProtocol, mpsc::Sender<(PeerId, Stream)>>,

    connections: HashMap<ConnectionId, Connection>,
    senders: HashMap<ConnectionId, mpsc::Sender<NewStream>>,

    /// Tracks channel pairs for a peer whilst we are dialing them.
    pending_channels: HashMap<PeerId, (mpsc::Sender<NewStream>, mpsc::Receiver<NewStream>)>,

    /// Sender for peers we want to dial.
    ///
    /// We manage this through a channel to avoid locks as part of
    /// [`NetworkBehaviour::poll`](libp2p_swarm::NetworkBehaviour::poll).
    dial_sender: mpsc::Sender<PeerId>,

    config: Config,
}

struct Connection {
    peer: PeerId,
    relayed: bool,
}

impl Shared {
    pub(crate) fn lock(shared: &Arc<Mutex<Shared>>) -> MutexGuard<'_, Shared> {
        shared.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Shared {
    pub(crate) fn new(dial_sender: mpsc::Sender<PeerId>, config: Config) -> Self {
        Self {
            dial_sender,
            config,
            connections: Default::default(),
            senders: Default::default(),
            pending_channels: Default::default(),
            supported_inbound_protocols: Default::default(),
        }
    }

    pub(crate) fn accept(
        &mut self,
        protocol: StreamProtocol,
    ) -> Result<IncomingStreams, AlreadyRegistered> {
        self.supported_inbound_protocols
            .retain(|_, sender| !sender.is_closed());

        if self.supported_inbound_protocols.contains_key(&protocol) {
            return Err(AlreadyRegistered);
        }

        let (sender, receiver) = mpsc::channel(0);
        self.supported_inbound_protocols
            .insert(protocol.clone(), sender);

        Ok(IncomingStreams::new(receiver))
    }

    /// Lists the protocols for which we have an active [`IncomingStreams`] instance.
    pub(crate) fn supported_inbound_protocols(&mut self) -> Vec<StreamProtocol> {
        self.supported_inbound_protocols
            .retain(|_, sender| !sender.is_closed());

        self.supported_inbound_protocols.keys().cloned().collect()
    }

    pub(crate) fn on_inbound_stream(
        &mut self,
        remote: PeerId,
        stream: Stream,
        protocol: StreamProtocol,
    ) {
        match self.supported_inbound_protocols.entry(protocol.clone()) {
            Entry::Occupied(mut entry) => match entry.get_mut().try_send((remote, stream)) {
                Ok(()) => {}
                Err(e) if e.is_full() => {
                    tracing::debug!(%protocol, "Channel is full, dropping inbound stream");
                }
                Err(e) if e.is_disconnected() => {
                    tracing::debug!(%protocol, "Channel is gone, dropping inbound stream");
                    entry.remove();
                }
                _ => unreachable!(),
            },
            Entry::Vacant(_) => {
                tracing::debug!(%protocol, "channel is gone, dropping inbound stream");
            }
        }
    }

    /// Whether streams may use a connection, given whether it is relayed.
    pub(crate) fn is_eligible(&self, relayed: bool) -> bool {
        !relayed || self.config.relayed_connections
    }

    pub(crate) fn on_connection_established(
        &mut self,
        conn: ConnectionId,
        peer: PeerId,
        relayed: bool,
    ) {
        self.connections.insert(conn, Connection { peer, relayed });
    }

    pub(crate) fn on_connection_closed(&mut self, conn: ConnectionId) {
        self.connections.remove(&conn);
    }

    pub(crate) fn on_dial_failure(&mut self, peer: PeerId, reason: String) {
        let Some((_, mut receiver)) = self.pending_channels.remove(&peer) else {
            return;
        };

        while let Ok(Some(new_stream)) = receiver.try_next() {
            let _ = new_stream
                .sender
                .send(Err(crate::OpenStreamError::Io(io::Error::new(
                    io::ErrorKind::NotConnected,
                    reason.clone(),
                ))));
        }
    }

    pub(crate) fn sender(&mut self, peer: PeerId) -> io::Result<mpsc::Sender<NewStream>> {
        let maybe_sender = self
            .connections
            .iter()
            .filter(|(_, c)| c.peer == peer && self.is_eligible(c.relayed))
            .map(|(id, _)| id)
            .choose(&mut rand::thread_rng())
            .and_then(|c| self.senders.get(c));

        match maybe_sender {
            Some(sender) => {
                tracing::debug!("Returning sender to existing connection");

                Ok(sender.clone())
            }
            None if !self.config.dialing => {
                tracing::debug!(%peer, "No eligible connection to peer and dialing is disabled");

                Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no eligible connection to peer and dialing is disabled",
                ))
            }
            None => {
                tracing::debug!(%peer, "No eligible connection to peer, initiating dial");

                let (sender, _) = self
                    .pending_channels
                    .entry(peer)
                    .or_insert_with(|| mpsc::channel(0));

                let _ = self.dial_sender.try_send(peer);

                Ok(sender.clone())
            }
        }
    }

    pub(crate) fn receiver(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        relayed: bool,
    ) -> mpsc::Receiver<NewStream> {
        if self.is_eligible(relayed)
            && let Some((sender, receiver)) = self.pending_channels.remove(&peer)
        {
            tracing::debug!(%peer, %connection, "Returning existing pending receiver");

            self.senders.insert(connection, sender);
            return receiver;
        }

        tracing::debug!(%peer, %connection, "Creating new channel pair");

        let (sender, receiver) = mpsc::channel(0);
        self.senders.insert(connection, sender);

        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared(config: Config) -> (Shared, mpsc::Receiver<PeerId>) {
        let (dial_sender, dial_receiver) = mpsc::channel(0);

        (Shared::new(dial_sender, config), dial_receiver)
    }

    /// Registers a connection the way [`Behaviour`](crate::Behaviour) does.
    fn connect(
        shared: &mut Shared,
        id: usize,
        peer: PeerId,
        relayed: bool,
    ) -> (ConnectionId, mpsc::Receiver<NewStream>) {
        let connection = ConnectionId::new_unchecked(id);
        let receiver = shared.receiver(peer, connection, relayed);
        shared.on_connection_established(connection, peer, relayed);

        (connection, receiver)
    }

    fn is_sender_of(shared: &Shared, sender: &mpsc::Sender<NewStream>, conn: ConnectionId) -> bool {
        sender.same_receiver(&shared.senders[&conn])
    }

    #[test]
    fn picks_only_direct_connections_when_relayed_are_disallowed() {
        let (mut shared, _dials) = shared(Config::default().with_relayed_connections(false));
        let peer = PeerId::random();
        connect(&mut shared, 0, peer, true);
        let (direct, _receiver) = connect(&mut shared, 1, peer, false);
        connect(&mut shared, 2, peer, true);

        for _ in 0..32 {
            let sender = shared.sender(peer).unwrap();
            assert!(is_sender_of(&shared, &sender, direct));
        }
    }

    #[test]
    fn picks_relayed_connections_by_default() {
        let (mut shared, _dials) = shared(Config::default());
        let peer = PeerId::random();
        let (relayed, _receiver) = connect(&mut shared, 0, peer, true);

        let sender = shared.sender(peer).unwrap();

        assert!(is_sender_of(&shared, &sender, relayed));
    }

    #[test]
    fn fails_without_dialing_when_only_relayed_connections_exist() {
        let (mut shared, mut dials) = shared(
            Config::default()
                .with_relayed_connections(false)
                .with_dialing(false),
        );
        let peer = PeerId::random();
        connect(&mut shared, 0, peer, true);

        let error = shared.sender(peer).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(dials.try_next().is_err(), "no dial is requested");
        assert!(shared.pending_channels.is_empty());
    }

    #[test]
    fn fails_without_dialing_when_not_connected() {
        let (mut shared, mut dials) = shared(Config::default().with_dialing(false));

        let error = shared.sender(PeerId::random()).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(dials.try_next().is_err(), "no dial is requested");
        assert!(shared.pending_channels.is_empty());
    }

    #[test]
    fn dials_when_only_relayed_connections_exist() {
        let (mut shared, mut dials) = shared(Config::default().with_relayed_connections(false));
        let peer = PeerId::random();
        connect(&mut shared, 0, peer, true);

        let sender = shared.sender(peer).unwrap();

        assert_eq!(dials.try_next().unwrap(), Some(peer));

        // A new relayed connection must not take over the streams waiting for the dial.
        let (relayed, _receiver) = connect(&mut shared, 1, peer, true);
        assert!(!is_sender_of(&shared, &sender, relayed));
        assert!(shared.pending_channels.contains_key(&peer));

        let (direct, _receiver) = connect(&mut shared, 2, peer, false);
        assert!(is_sender_of(&shared, &sender, direct));
        assert!(shared.pending_channels.is_empty());
    }
}
