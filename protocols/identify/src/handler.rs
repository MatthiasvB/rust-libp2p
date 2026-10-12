// Copyright 2018 Parity Technologies (UK) Ltd.
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

use std::{
    cmp::Reverse,
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use either::Either;
use futures::prelude::*;
use futures_bounded::Timeout;
use futures_timer::Delay;
use libp2p_core::{
    Multiaddr, PeerRecord,
    multiaddr::Protocol,
    upgrade::{ReadyUpgrade, SelectUpgrade},
};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    ConnectionHandler, ConnectionHandlerEvent, StreamProtocol, StreamUpgradeError,
    SubstreamProtocol, SupportedProtocols,
    handler::{
        ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        ProtocolSupport,
    },
};
use smallvec::SmallVec;
use tracing::Level;

use crate::{
    PROTOCOL_NAME, PUSH_PROTOCOL_NAME,
    behaviour::KeyType,
    protocol::{self, Info, MAX_MESSAGE_SIZE_BYTES, PushInfo, UpgradeError},
};

const STREAM_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 10;

/// Protocol handler for sending and receiving identification requests.
///
/// Outbound requests are sent periodically. The handler performs expects
/// at least one identification request to be answered by the remote before
/// permitting the underlying connection to be closed.
pub struct Handler {
    remote_peer_id: PeerId,
    /// Pending events to yield.
    events: SmallVec<
        [ConnectionHandlerEvent<
            Either<ReadyUpgrade<StreamProtocol>, ReadyUpgrade<StreamProtocol>>,
            (),
            Event,
        >; 4],
    >,

    active_streams: futures_bounded::FuturesSet<Result<Success, UpgradeError>>,

    /// Future that fires when we need to identify the node again.
    trigger_next_identify: Delay,

    /// Whether we have exchanged at least one periodic identify.
    exchanged_one_periodic_identify: bool,

    /// The interval of `trigger_next_identify`, i.e. the recurrent delay.
    interval: Duration,

    /// The key of the local peer.
    local_key: Arc<KeyType>,

    /// Application-specific version of the protocol family used by the peer,
    /// e.g. `ipfs/1.0.0` or `polkadot/1.0.0`.
    protocol_version: String,

    /// Name and version of the peer, similar to the `User-Agent` header in
    /// the HTTP protocol.
    agent_version: String,

    /// Address observed by or for the remote.
    observed_addr: Multiaddr,

    /// Identify information about the remote peer.
    remote_info: Option<Info>,

    local_supported_protocols: SupportedProtocols,
    remote_supported_protocols: HashSet<StreamProtocol>,
    external_addresses: HashSet<Multiaddr>,
}

/// An event from `Behaviour` with the information requested by the `Handler`.
#[derive(Debug)]
pub enum InEvent {
    AddressesChanged(HashSet<Multiaddr>),
    Push,
}

/// Event produced by the `Handler`.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// We obtained identification information from the remote.
    Identified(Info),
    /// We replied to an identification request from the remote.
    Identification,
    /// We actively pushed our identification information to the remote.
    IdentificationPushed(Info),
    /// Failed to identify the remote, or to reply to an identification request.
    IdentificationError(StreamUpgradeError<UpgradeError>),
}

impl Handler {
    /// Creates a new `Handler`.
    pub(crate) fn new(
        interval: Duration,
        remote_peer_id: PeerId,
        local_key: Arc<KeyType>,
        protocol_version: String,
        agent_version: String,
        observed_addr: Multiaddr,
        external_addresses: HashSet<Multiaddr>,
    ) -> Self {
        Self {
            remote_peer_id,
            events: SmallVec::new(),
            active_streams: futures_bounded::FuturesSet::new(
                move || futures_bounded::Delay::futures_timer(STREAM_TIMEOUT),
                MAX_CONCURRENT_STREAMS_PER_CONNECTION,
            ),
            trigger_next_identify: Delay::new(Duration::ZERO),
            exchanged_one_periodic_identify: false,
            interval,
            local_key,
            protocol_version,
            agent_version,
            observed_addr,
            local_supported_protocols: SupportedProtocols::default(),
            remote_supported_protocols: HashSet::default(),
            remote_info: Default::default(),
            external_addresses,
        }
    }

    fn on_fully_negotiated_inbound(
        &mut self,
        FullyNegotiatedInbound {
            protocol: output, ..
        }: FullyNegotiatedInbound<<Self as ConnectionHandler>::InboundProtocol>,
    ) {
        match output {
            future::Either::Left(stream) => {
                let info = self.build_info();

                if self
                    .active_streams
                    .try_push(
                        protocol::send_identify(stream, info).map_ok(|_| Success::SentIdentify),
                    )
                    .is_err()
                {
                    tracing::warn!("Dropping inbound stream because we are at capacity");
                } else {
                    self.exchanged_one_periodic_identify = true;
                }
            }
            future::Either::Right(stream) => {
                if self
                    .active_streams
                    .try_push(protocol::recv_push(stream).map_ok(Success::ReceivedIdentifyPush))
                    .is_err()
                {
                    tracing::warn!(
                        "Dropping inbound identify push stream because we are at capacity"
                    );
                }
            }
        }
    }

    fn on_fully_negotiated_outbound(
        &mut self,
        FullyNegotiatedOutbound {
            protocol: output, ..
        }: FullyNegotiatedOutbound<<Self as ConnectionHandler>::OutboundProtocol>,
    ) {
        match output {
            future::Either::Left(stream) => {
                if self
                    .active_streams
                    .try_push(protocol::recv_identify(stream).map_ok(Success::ReceivedIdentify))
                    .is_err()
                {
                    tracing::warn!("Dropping outbound identify stream because we are at capacity");
                }
            }
            future::Either::Right(stream) => {
                let info = self.build_info();

                if self
                    .active_streams
                    .try_push(
                        protocol::send_identify(stream, info).map_ok(Success::SentIdentifyPush),
                    )
                    .is_err()
                {
                    tracing::warn!(
                        "Dropping outbound identify push stream because we are at capacity"
                    );
                }
            }
        }
    }

    /// Builds our identify message, keeping only the highest-ranked addresses if all of them
    /// would exceed [`MAX_MESSAGE_SIZE_BYTES`].
    fn build_info(&mut self) -> Info {
        let mut addresses = Vec::from_iter(self.external_addresses.iter().cloned());
        rank_addresses(&mut addresses);

        let info = self.info_with_addresses(addresses.clone());
        let len = protocol::encoded_len(&info);
        if len <= MAX_MESSAGE_SIZE_BYTES {
            return info;
        }

        let signed = info.signed_peer_record.is_some();
        let costs = Vec::from_iter(addresses.iter().map(|a| address_cost(a, signed)));
        let base = len.saturating_sub(costs.iter().sum());
        let mut kept = costs
            .iter()
            .scan(base, |used, cost| {
                *used += cost;
                (*used <= MAX_MESSAGE_SIZE_BYTES).then_some(())
            })
            .count();

        // The estimate ignores changes in the width of length prefixes and in signature size.
        let mut info = self.info_with_addresses(addresses[..kept].to_vec());
        let mut len = protocol::encoded_len(&info);
        while len > MAX_MESSAGE_SIZE_BYTES && kept > 0 {
            kept -= 1;
            info = self.info_with_addresses(addresses[..kept].to_vec());
            len = protocol::encoded_len(&info);
        }

        if len > MAX_MESSAGE_SIZE_BYTES {
            tracing::warn!(
                peer=%self.remote_peer_id,
                len,
                max=MAX_MESSAGE_SIZE_BYTES,
                "Identify message exceeds the size limit even without addresses"
            );
        } else {
            tracing::debug!(
                peer=%self.remote_peer_id,
                kept,
                total=addresses.len(),
                "Dropped the lowest-ranked addresses to fit the identify message size limit"
            );
        }
        info
    }

    fn info_with_addresses(&self, addresses: Vec<Multiaddr>) -> Info {
        let signed_envelope = match self.local_key.as_ref() {
            KeyType::PublicKey(_) => None,
            KeyType::Keypair { keypair, .. } => PeerRecord::new(keypair, addresses.clone())
                .ok()
                .map(|r| r.into_signed_envelope()),
        };
        Info {
            public_key: self.local_key.public_key().clone(),
            protocol_version: self.protocol_version.clone(),
            agent_version: self.agent_version.clone(),
            listen_addrs: addresses,
            protocols: Vec::from_iter(self.local_supported_protocols.iter().cloned()),
            observed_addr: self.observed_addr.clone(),
            signed_peer_record: signed_envelope,
        }
    }

    /// If the public key matches the remote peer, handles the given `info` and returns `true`.
    fn handle_incoming_info(&mut self, info: &Info) -> bool {
        let derived_peer_id = info.public_key.to_peer_id();
        if self.remote_peer_id != derived_peer_id {
            return false;
        }

        self.remote_info.replace(info.clone());

        self.update_supported_protocols_for_remote(info);
        true
    }

    fn update_supported_protocols_for_remote(&mut self, remote_info: &Info) {
        let new_remote_protocols = HashSet::from_iter(remote_info.protocols.clone());

        let remote_added_protocols = new_remote_protocols
            .difference(&self.remote_supported_protocols)
            .cloned()
            .collect::<HashSet<_>>();
        let remote_removed_protocols = self
            .remote_supported_protocols
            .difference(&new_remote_protocols)
            .cloned()
            .collect::<HashSet<_>>();

        if !remote_added_protocols.is_empty() {
            self.events
                .push(ConnectionHandlerEvent::ReportRemoteProtocols(
                    ProtocolSupport::Added(remote_added_protocols),
                ));
        }

        if !remote_removed_protocols.is_empty() {
            self.events
                .push(ConnectionHandlerEvent::ReportRemoteProtocols(
                    ProtocolSupport::Removed(remote_removed_protocols),
                ));
        }

        self.remote_supported_protocols = new_remote_protocols;
    }

    fn local_protocols_to_string(&mut self) -> String {
        self.local_supported_protocols
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = InEvent;
    type ToBehaviour = Event;
    type InboundProtocol =
        SelectUpgrade<ReadyUpgrade<StreamProtocol>, ReadyUpgrade<StreamProtocol>>;
    type OutboundProtocol = Either<ReadyUpgrade<StreamProtocol>, ReadyUpgrade<StreamProtocol>>;
    type OutboundOpenInfo = ();
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(
            SelectUpgrade::new(
                ReadyUpgrade::new(PROTOCOL_NAME),
                ReadyUpgrade::new(PUSH_PROTOCOL_NAME),
            ),
            (),
        )
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            InEvent::AddressesChanged(addresses) => {
                self.external_addresses = addresses;
            }
            InEvent::Push => {
                self.events
                    .push(ConnectionHandlerEvent::OutboundSubstreamRequest {
                        protocol: SubstreamProtocol::new(
                            Either::Right(ReadyUpgrade::new(PUSH_PROTOCOL_NAME)),
                            (),
                        ),
                    });
            }
        }
    }

    #[tracing::instrument(level = "trace", name = "ConnectionHandler::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, (), Event>> {
        if let Some(event) = self.events.pop() {
            return Poll::Ready(event);
        }

        // Poll the future that fires when we need to identify the node again.
        if let Poll::Ready(()) = self.trigger_next_identify.poll_unpin(cx) {
            self.trigger_next_identify.reset(self.interval);
            let event = ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(
                    Either::Left(ReadyUpgrade::new(PROTOCOL_NAME)),
                    (),
                ),
            };
            return Poll::Ready(event);
        }

        while let Poll::Ready(ready) = self.active_streams.poll_unpin(cx) {
            match ready {
                Ok(Ok(Success::ReceivedIdentify(remote_info))) => {
                    if self.handle_incoming_info(&remote_info) {
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                            Event::Identified(remote_info),
                        ));
                    } else {
                        tracing::warn!(
                            %self.remote_peer_id,
                            ?remote_info.public_key,
                            derived_peer_id=%remote_info.public_key.to_peer_id(),
                            "Discarding received identify message as public key does not match remote peer ID",
                        );
                    }
                }
                Ok(Ok(Success::SentIdentifyPush(info))) => {
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::IdentificationPushed(info),
                    ));
                }
                Ok(Ok(Success::SentIdentify)) => {
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::Identification,
                    ));
                }
                Ok(Ok(Success::ReceivedIdentifyPush(remote_push_info))) => {
                    if let Some(mut info) = self.remote_info.clone() {
                        info.merge(remote_push_info);

                        if self.handle_incoming_info(&info) {
                            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                                Event::Identified(info),
                            ));
                        } else {
                            tracing::warn!(
                                %self.remote_peer_id,
                                ?info.public_key,
                                derived_peer_id=%info.public_key.to_peer_id(),
                                "Discarding received identify message as public key does not match remote peer ID",
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::IdentificationError(StreamUpgradeError::Apply(e)),
                    ));
                }
                Err(Timeout { .. }) => {
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::IdentificationError(StreamUpgradeError::Timeout),
                    ));
                }
            }
        }

        Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(fully_negotiated_inbound) => {
                self.on_fully_negotiated_inbound(fully_negotiated_inbound)
            }
            ConnectionEvent::FullyNegotiatedOutbound(fully_negotiated_outbound) => {
                self.on_fully_negotiated_outbound(fully_negotiated_outbound)
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError { error, .. }) => {
                self.events.push(ConnectionHandlerEvent::NotifyBehaviour(
                    Event::IdentificationError(
                        #[allow(unused)]
                        error.map_upgrade_err(|e| libp2p_core::util::unreachable(e.into_inner())),
                    ),
                ));
                self.trigger_next_identify.reset(self.interval);
            }
            ConnectionEvent::LocalProtocolsChange(change) => {
                let before = tracing::enabled!(Level::DEBUG)
                    .then(|| self.local_protocols_to_string())
                    .unwrap_or_default();
                let protocols_changed = self.local_supported_protocols.on_protocols_change(change);
                let after = tracing::enabled!(Level::DEBUG)
                    .then(|| self.local_protocols_to_string())
                    .unwrap_or_default();

                if protocols_changed && self.exchanged_one_periodic_identify {
                    tracing::debug!(
                        peer=%self.remote_peer_id,
                        %before,
                        %after,
                        "Supported listen protocols changed, pushing to peer"
                    );

                    self.events
                        .push(ConnectionHandlerEvent::OutboundSubstreamRequest {
                            protocol: SubstreamProtocol::new(
                                Either::Right(ReadyUpgrade::new(PUSH_PROTOCOL_NAME)),
                                (),
                            ),
                        });
                }
            }
            _ => {}
        }
    }
}

enum Success {
    SentIdentify,
    ReceivedIdentify(Info),
    SentIdentifyPush(Info),
    ReceivedIdentifyPush(PushInfo),
}

/// Sorts addresses best first, in the order go-libp2p uses to trim its own identify message:
/// public before private before loopback, then by transport. The sort is stable.
fn rank_addresses(addresses: &mut [Multiaddr]) {
    addresses.sort_by_key(|address| Reverse(address_rank(address)));
}

fn address_rank(address: &Multiaddr) -> (u8, u8) {
    (scope_rank(address), transport_rank(address))
}

/// A circuit address ranks by its first hop, the relay.
fn scope_rank(address: &Multiaddr) -> u8 {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) if ip.is_loopback() => 0,
        Some(Protocol::Ip6(ip)) if ip.is_loopback() => 0,
        Some(Protocol::Ip4(ip)) if is_public_ipv4(ip) => 2,
        Some(Protocol::Ip6(ip)) if is_public_ipv6(ip) => 2,
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)) => 2,
        _ => 1,
    }
}

/// Layered transports follow the transport they run on, so the last match before the first
/// `/p2p` decides. A circuit address thus ranks by the transport to its relay.
fn transport_rank(address: &Multiaddr) -> u8 {
    address
        .iter()
        .take_while(|protocol| !matches!(protocol, Protocol::P2p(_)))
        .fold(0, |rank, protocol| match protocol {
            Protocol::QuicV1 => 5,
            Protocol::Tcp(_) => 4,
            Protocol::Tls | Protocol::Ws(_) | Protocol::Wss(_) => 3,
            Protocol::WebTransport => 2,
            Protocol::WebRTCDirect => 1,
            _ => rank,
        })
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    let shared = first == 100 && (second & 0b1100_0000) == 0b0100_0000;
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || shared)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let [first, second, ..] = ip.segments();
    let documentation = first == 0x2001 && second == 0x0db8;
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || documentation)
}

/// The bytes an address adds to the message: its `listen_addrs` entry, plus its `AddressInfo`
/// entry if the message carries a signed peer record.
fn address_cost(address: &Multiaddr, signed: bool) -> usize {
    let field = |len: usize| 1 + prost::length_delimiter_len(len) + len;
    let listen_entry = field(address.len());
    if signed {
        listen_entry + field(listen_entry)
    } else {
        listen_entry
    }
}

#[cfg(test)]
mod tests {
    use libp2p_core::multihash::Multihash;
    use libp2p_identity::Keypair;

    use super::*;

    fn relay_addresses(relay_ip: Ipv4Addr, local_peer_id: PeerId) -> Vec<Multiaddr> {
        let relay = PeerId::random();
        let ip = Multiaddr::empty().with(Protocol::Ip4(relay_ip));
        let certhash = |seed| Protocol::Certhash(Multihash::wrap(0x12, &[seed; 32]).unwrap());
        [
            ip.clone().with(Protocol::Udp(4001)).with(Protocol::QuicV1),
            ip.clone().with(Protocol::Tcp(4001)),
            ip.clone()
                .with(Protocol::Tcp(4002))
                .with(Protocol::Tls)
                .with(Protocol::Ws("/".into())),
            ip.clone()
                .with(Protocol::Udp(4001))
                .with(Protocol::QuicV1)
                .with(Protocol::WebTransport)
                .with(certhash(1))
                .with(certhash(2)),
            ip.with(Protocol::Udp(4003))
                .with(Protocol::WebRTCDirect)
                .with(certhash(3)),
        ]
        .into_iter()
        .map(|address| {
            address
                .with(Protocol::P2p(relay))
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(local_peer_id))
        })
        .collect()
    }

    fn circuit_addresses(relays: u8, local_peer_id: PeerId) -> Vec<Multiaddr> {
        (0..relays)
            .flat_map(|i| relay_addresses(Ipv4Addr::new(88, 99, 240, 155 + i), local_peer_id))
            .collect()
    }

    fn handler(key: KeyType, addresses: impl IntoIterator<Item = Multiaddr>) -> Handler {
        Handler::new(
            Duration::from_secs(300),
            PeerId::random(),
            Arc::new(key),
            "/test/1.0.0".to_string(),
            "test".to_string(),
            "/ip4/203.0.113.7/tcp/4001".parse().unwrap(),
            HashSet::from_iter(addresses),
        )
    }

    fn signing_handler(
        addresses: impl FnOnce(PeerId) -> Vec<Multiaddr>,
    ) -> (Handler, Vec<Multiaddr>) {
        let keypair = Keypair::generate_ed25519();
        let addresses = addresses(keypair.public().to_peer_id());
        (
            handler(KeyType::from(&keypair), addresses.clone()),
            addresses,
        )
    }

    fn ranked(mut addresses: Vec<Multiaddr>) -> Vec<Multiaddr> {
        rank_addresses(&mut addresses);
        addresses
    }

    /// Equal ranks keep the order of the handler's address set, so compare by rank.
    fn assert_top_ranked(kept: &[Multiaddr], all: &[Multiaddr]) {
        assert!(
            kept.windows(2)
                .all(|pair| address_rank(&pair[0]) >= address_rank(&pair[1]))
        );
        let lowest_kept = kept.iter().map(address_rank).min().unwrap();
        assert!(
            all.iter()
                .filter(|address| !kept.contains(address))
                .all(|address| address_rank(address) <= lowest_kept)
        );
    }

    #[test]
    fn ranks_addresses_in_go_order() {
        let relay = PeerId::random();
        let [a, b, c, d, e, f, g, h, i] = [
            "/ip4/88.99.240.155/udp/4001/quic-v1".to_string(),
            "/ip4/88.99.240.155/tcp/4001".to_string(),
            "/dns4/relay.example/tcp/4001".to_string(),
            "/ip4/88.99.240.155/tcp/443/tls/ws".to_string(),
            "/ip4/88.99.240.155/udp/4001/quic-v1/webtransport".to_string(),
            "/ip4/88.99.240.155/udp/4002/webrtc-direct".to_string(),
            format!("/ip4/10.0.0.1/udp/4001/quic-v1/p2p/{relay}/p2p-circuit"),
            "/memory/1234".to_string(),
            "/ip4/127.0.0.1/udp/4001/quic-v1".to_string(),
        ]
        .map(|address| address.parse::<Multiaddr>().unwrap());

        assert_eq!(
            ranked(vec![
                i.clone(),
                h.clone(),
                b.clone(),
                g.clone(),
                f.clone(),
                c.clone(),
                e.clone(),
                d.clone(),
                a.clone()
            ]),
            vec![a, b, c, d, e, f, g, h, i]
        );
    }

    #[test]
    fn keeps_every_address_that_fits() {
        let (mut handler, addresses) = signing_handler(|me| circuit_addresses(1, me));

        let info = handler.build_info();

        assert_eq!(
            HashSet::<_>::from_iter(info.listen_addrs.iter()),
            HashSet::from_iter(addresses.iter())
        );
        assert_top_ranked(&info.listen_addrs, &addresses);
    }

    #[test]
    fn trimmed_message_fits_the_limit() {
        let (mut handler, addresses) = signing_handler(|me| circuit_addresses(4, me));

        let info = handler.build_info();

        assert!(!info.listen_addrs.is_empty());
        assert!(info.listen_addrs.len() < addresses.len());
        assert!(protocol::encoded_len(&info) <= MAX_MESSAGE_SIZE_BYTES);
    }

    #[test]
    fn trimmed_record_verifies_and_matches_listen_addrs() {
        let (mut handler, _) = signing_handler(|me| circuit_addresses(4, me));

        let info = handler.build_info();

        let record = PeerRecord::from_signed_envelope(info.signed_peer_record.unwrap())
            .expect("record to verify");
        assert_eq!(record.addresses(), info.listen_addrs.as_slice());
    }

    #[test]
    fn keeps_the_highest_ranked_addresses() {
        let (mut handler, addresses) = signing_handler(|me| circuit_addresses(4, me));

        let info = handler.build_info();

        assert_top_ranked(&info.listen_addrs, &addresses);
        assert!(
            addresses
                .iter()
                .filter(|address| transport_rank(address) >= 4)
                .all(|address| info.listen_addrs.contains(address))
        );
    }

    #[test]
    fn trims_without_a_signed_record() {
        let keypair = Keypair::generate_ed25519();
        let addresses = circuit_addresses(8, keypair.public().to_peer_id());
        let mut handler = handler(KeyType::from(keypair.public()), addresses.clone());

        let info = handler.build_info();

        assert!(info.signed_peer_record.is_none());
        assert!(info.listen_addrs.len() < addresses.len());
        assert!(protocol::encoded_len(&info) <= MAX_MESSAGE_SIZE_BYTES);
        assert_top_ranked(&info.listen_addrs, &addresses);
    }

    #[test]
    fn oversized_message_drops_every_address() {
        let (mut handler, _) = signing_handler(|me| circuit_addresses(1, me));
        handler.protocol_version = "x".repeat(MAX_MESSAGE_SIZE_BYTES);

        let info = handler.build_info();

        assert!(info.listen_addrs.is_empty());
    }
}
