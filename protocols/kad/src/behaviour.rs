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

//! Implementation of the `Kademlia` network behaviour.

mod test;

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
    time::Duration,
    vec,
};

use fnv::FnvHashSet;
use libp2p_core::{transport::PortUse, ConnectedPoint, Endpoint, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    behaviour::{AddressChange, ConnectionClosed, ConnectionEstablished, DialFailure, FromSwarm},
    dial_opts::{self, DialOpts},
    ConnectionDenied, ConnectionHandler, ConnectionId, DialError, ExternalAddresses,
    ListenAddresses, NetworkBehaviour, NotifyHandler, StreamProtocol, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use thiserror::Error;
use tracing::Level;
use web_time::Instant;

pub use crate::query::QueryStats;
use crate::{
    addresses::Addresses,
    bootstrap,
    handler::{Handler, HandlerEvent, HandlerIn, RequestId},
    jobs::*,
    kbucket::{self, Distance, KBucketConfig, KBucketsTable, NodeStatus},
    protocol,
    protocol::{ConnectionType, KadPeer, ProtocolConfig},
    query::{Query, QueryConfig, QueryId, QueryPool, QueryPoolState},
    record::{
        self,
        store::{self, RecordStore},
        ProviderRecord, Record,
    },
    K_VALUE,
};

/// `Behaviour` is a `NetworkBehaviour` that implements the libp2p
/// Kademlia protocol.
pub struct Behaviour<TStore> {
    /// The Kademlia routing table.
    kbuckets: KBucketsTable<kbucket::Key<PeerId>, Addresses>,

    /// The k-bucket insertion strategy.
    kbucket_inserts: BucketInserts,

    /// Configuration of the wire protocol.
    protocol_config: ProtocolConfig,

    /// Configuration of [`RecordStore`] filtering.
    record_filtering: StoreInserts,

    /// The currently active (i.e. in-progress) queries.
    queries: QueryPool,

    /// The currently connected peers.
    ///
    /// This is a superset of the connected peers currently in the routing table.
    connected_peers: FnvHashSet<PeerId>,

    /// Periodic job for re-publication of provider records for keys
    /// provided by the local node.
    add_provider_job: Option<AddProviderJob>,

    /// Periodic job for (re-)replication and (re-)publishing of
    /// regular (value-)records.
    put_record_job: Option<PutRecordJob>,

    /// The TTL of regular (value-)records.
    record_ttl: Option<Duration>,

    /// The TTL of provider records.
    provider_record_ttl: Option<Duration>,

    /// Queued events to return when the behaviour is being polled.
    queued_events: VecDeque<ToSwarm<Event, HandlerIn>>,

    listen_addresses: ListenAddresses,

    external_addresses: ExternalAddresses,

    connections: HashMap<ConnectionId, PeerId>,

    /// See [`Config::caching`].
    caching: Caching,

    local_peer_id: PeerId,

    mode: Mode,
    auto_mode: bool,
    no_events_waker: Option<Waker>,

    /// The record storage.
    store: TStore,

    /// Tracks the status of the current bootstrap.
    bootstrap_status: bootstrap::Status,
}

/// The configurable strategies for the insertion of peers
/// and their addresses into the k-buckets of the Kademlia
/// routing table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BucketInserts {
    /// Whenever a connection to a peer is established as a
    /// result of a dialing attempt and that peer is not yet
    /// in the routing table, it is inserted as long as there
    /// is a free slot in the corresponding k-bucket. If the
    /// k-bucket is full but still has a free pending slot,
    /// it may be inserted into the routing table at a later time if an unresponsive
    /// disconnected peer is evicted from the bucket.
    OnConnected,
    /// New peers and addresses are only added to the routing table via
    /// explicit calls to [`Behaviour::add_address`].
    ///
    /// > **Note**: Even though peers can only get into the
    /// > routing table as a result of [`Behaviour::add_address`],
    /// > routing table entries are still updated as peers
    /// > connect and disconnect (i.e. the order of the entries
    /// > as well as the network addresses).
    Manual,
}

/// The configurable filtering strategies for the acceptance of
/// incoming records.
///
/// This can be used for e.g. signature verification or validating
/// the accompanying [`Key`].
///
/// [`Key`]: crate::record::Key
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StoreInserts {
    /// Whenever a (provider) record is received,
    /// the record is forwarded immediately to the [`RecordStore`].
    Unfiltered,
    /// Whenever a (provider) record is received, an event is emitted.
    /// Provider records generate a [`InboundRequest::AddProvider`] under
    /// [`Event::InboundRequest`], normal records generate a [`InboundRequest::PutRecord`]
    /// under [`Event::InboundRequest`].
    ///
    /// When deemed valid, a (provider) record needs to be explicitly stored in
    /// the [`RecordStore`] via [`RecordStore::put`] or [`RecordStore::add_provider`],
    /// whichever is applicable. A mutable reference to the [`RecordStore`] can
    /// be retrieved via [`Behaviour::store_mut`].
    FilterBoth,
}

/// The configuration for the `Kademlia` behaviour.
///
/// The configuration is consumed by [`Behaviour::new`].
#[derive(Debug, Clone)]
pub struct Config {
    kbucket_config: KBucketConfig,
    query_config: QueryConfig,
    protocol_config: ProtocolConfig,
    record_ttl: Option<Duration>,
    record_replication_interval: Option<Duration>,
    record_publication_interval: Option<Duration>,
    record_filtering: StoreInserts,
    provider_record_ttl: Option<Duration>,
    provider_publication_interval: Option<Duration>,
    kbucket_inserts: BucketInserts,
    caching: Caching,
    periodic_bootstrap_interval: Option<Duration>,
    automatic_bootstrap_throttle: Option<Duration>,
}

impl Default for Config {
    /// Returns the default configuration.
    ///
    /// Deprecated: use `Config::new` instead.
    fn default() -> Self {
        Self::new(protocol::DEFAULT_PROTO_NAME)
    }
}

/// The configuration for Kademlia "write-back" caching after successful
/// lookups via [`Behaviour::get_record`].
#[derive(Debug, Clone)]
pub enum Caching {
    /// Caching is disabled and the peers closest to records being looked up
    /// that do not return a record are not tracked, i.e.
    /// [`GetRecordOk::FinishedWithNoAdditionalRecord`] is always empty.
    Disabled,
    /// Up to `max_peers` peers not returning a record that are closest to the key
    /// being looked up are tracked and returned in
    /// [`GetRecordOk::FinishedWithNoAdditionalRecord`]. The write-back operation must be
    /// performed explicitly, if desired and after choosing a record from the results, via
    /// [`Behaviour::put_record_to`].
    Enabled { max_peers: u16 },
}

impl Config {
    /// Builds a new `Config` with the given protocol name.
    pub fn new(protocol_name: StreamProtocol) -> Self {
        Config {
            kbucket_config: KBucketConfig::default(),
            query_config: QueryConfig::default(),
            protocol_config: ProtocolConfig::new(protocol_name),
            record_ttl: Some(Duration::from_secs(48 * 60 * 60)),
            record_replication_interval: Some(Duration::from_secs(60 * 60)),
            record_publication_interval: Some(Duration::from_secs(22 * 60 * 60)),
            record_filtering: StoreInserts::Unfiltered,
            provider_publication_interval: Some(Duration::from_secs(12 * 60 * 60)),
            provider_record_ttl: Some(Duration::from_secs(48 * 60 * 60)),
            kbucket_inserts: BucketInserts::OnConnected,
            caching: Caching::Enabled { max_peers: 1 },
            periodic_bootstrap_interval: Some(Duration::from_secs(5 * 60)),
            automatic_bootstrap_throttle: Some(bootstrap::DEFAULT_AUTOMATIC_THROTTLE),
        }
    }

    /// Sets the timeout for a single query.
    ///
    /// > **Note**: A single query usually comprises at least as many requests
    /// > as the replication factor, i.e. this is not a request timeout.
    ///
    /// The default is 60 seconds.
    pub fn set_query_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.query_config.timeout = timeout;
        self
    }

    /// Sets the replication factor to use.
    ///
    /// The replication factor determines to how many closest peers
    /// a record is replicated. The default is [`crate::K_VALUE`].
    pub fn set_replication_factor(&mut self, replication_factor: NonZeroUsize) -> &mut Self {
        self.query_config.replication_factor = replication_factor;
        self
    }

    /// Sets the allowed level of parallelism for iterative queries.
    ///
    /// The `α` parameter in the Kademlia paper. The maximum number of peers
    /// that an iterative query is allowed to wait for in parallel while
    /// iterating towards the closest nodes to a target. Defaults to
    /// `ALPHA_VALUE`.
    ///
    /// This only controls the level of parallelism of an iterative query, not
    /// the level of parallelism of a query to a fixed set of peers.
    ///
    /// When used with [`Config::disjoint_query_paths`] it equals
    /// the amount of disjoint paths used.
    pub fn set_parallelism(&mut self, parallelism: NonZeroUsize) -> &mut Self {
        self.query_config.parallelism = parallelism;
        self
    }

    /// Require iterative queries to use disjoint paths for increased resiliency
    /// in the presence of potentially adversarial nodes.
    ///
    /// When enabled the number of disjoint paths used equals the configured
    /// parallelism.
    ///
    /// See the S/Kademlia paper for more information on the high level design
    /// as well as its security improvements.
    pub fn disjoint_query_paths(&mut self, enabled: bool) -> &mut Self {
        self.query_config.disjoint_query_paths = enabled;
        self
    }

    /// Sets the TTL for stored records.
    ///
    /// The TTL should be significantly longer than the (re-)publication
    /// interval, to avoid premature expiration of records. The default is 36
    /// hours.
    ///
    /// `None` means records never expire.
    ///
    /// Does not apply to provider records.
    pub fn set_record_ttl(&mut self, record_ttl: Option<Duration>) -> &mut Self {
        self.record_ttl = record_ttl;
        self
    }

    /// Sets whether or not records should be filtered before being stored.
    ///
    /// See [`StoreInserts`] for the different values.
    /// Defaults to [`StoreInserts::Unfiltered`].
    pub fn set_record_filtering(&mut self, filtering: StoreInserts) -> &mut Self {
        self.record_filtering = filtering;
        self
    }

    /// Sets the (re-)replication interval for stored records.
    ///
    /// Periodic replication of stored records ensures that the records
    /// are always replicated to the available nodes closest to the key in the
    /// context of DHT topology changes (i.e. nodes joining and leaving), thus
    /// ensuring persistence until the record expires. Replication does not
    /// prolong the regular lifetime of a record (for otherwise it would live
    /// forever regardless of the configured TTL). The expiry of a record
    /// is only extended through re-publication.
    ///
    /// This interval should be significantly shorter than the publication
    /// interval, to ensure persistence between re-publications. The default
    /// is 1 hour.
    ///
    /// `None` means that stored records are never re-replicated.
    ///
    /// Does not apply to provider records.
    pub fn set_replication_interval(&mut self, interval: Option<Duration>) -> &mut Self {
        self.record_replication_interval = interval;
        self
    }

    /// Sets the (re-)publication interval of stored records.
    ///
    /// Records persist in the DHT until they expire. By default, published
    /// records are re-published in regular intervals for as long as the record
    /// exists in the local storage of the original publisher, thereby extending
    /// the records lifetime.
    ///
    /// This interval should be significantly shorter than the record TTL, to
    /// ensure records do not expire prematurely. The default is 24 hours.
    ///
    /// `None` means that stored records are never automatically re-published.
    ///
    /// Does not apply to provider records.
    pub fn set_publication_interval(&mut self, interval: Option<Duration>) -> &mut Self {
        self.record_publication_interval = interval;
        self
    }

    /// Sets the TTL for provider records.
    ///
    /// `None` means that stored provider records never expire.
    ///
    /// Must be significantly larger than the provider publication interval.
    pub fn set_provider_record_ttl(&mut self, ttl: Option<Duration>) -> &mut Self {
        self.provider_record_ttl = ttl;
        self
    }

    /// Sets the interval at which provider records for keys provided
    /// by the local node are re-published.
    ///
    /// `None` means that stored provider records are never automatically
    /// re-published.
    ///
    /// Must be significantly less than the provider record TTL.
    pub fn set_provider_publication_interval(&mut self, interval: Option<Duration>) -> &mut Self {
        self.provider_publication_interval = interval;
        self
    }

    /// Modifies the maximum allowed size of individual Kademlia packets.
    ///
    /// It might be necessary to increase this value if trying to put large
    /// records.
    pub fn set_max_packet_size(&mut self, size: usize) -> &mut Self {
        self.protocol_config.set_max_packet_size(size);
        self
    }

    /// Sets the k-bucket insertion strategy for the Kademlia routing table.
    pub fn set_kbucket_inserts(&mut self, inserts: BucketInserts) -> &mut Self {
        self.kbucket_inserts = inserts;
        self
    }

    /// Sets the [`Caching`] strategy to use for successful lookups.
    ///
    /// The default is [`Caching::Enabled`] with a `max_peers` of 1.
    /// Hence, with default settings and a lookup quorum of 1, a successful lookup
    /// will result in the record being cached at the closest node to the key that
    /// did not return the record, i.e. the standard Kademlia behaviour.
    pub fn set_caching(&mut self, c: Caching) -> &mut Self {
        self.caching = c;
        self
    }

    /// Sets the interval on which [`Behaviour::bootstrap`] is called periodically.
    ///
    /// * Default to `5` minutes.
    /// * Set to `None` to disable periodic bootstrap.
    pub fn set_periodic_bootstrap_interval(&mut self, interval: Option<Duration>) -> &mut Self {
        self.periodic_bootstrap_interval = interval;
        self
    }

    /// Sets the configuration for the k-buckets.
    ///
    /// * Default to K_VALUE.
    ///
    /// **WARNING**: setting a `size` higher that `K_VALUE` may imply additional memory allocations.
    pub fn set_kbucket_size(&mut self, size: NonZeroUsize) -> &mut Self {
        self.kbucket_config.set_bucket_size(size);
        self
    }

    /// Sets the timeout duration after creation of a pending entry after which
    /// it becomes eligible for insertion into a full bucket, replacing the
    /// least-recently (dis)connected node.
    ///
    /// * Default to `60` s.
    pub fn set_kbucket_pending_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.kbucket_config.set_pending_timeout(timeout);
        self
    }

    /// Sets the time to wait before calling [`Behaviour::bootstrap`] after a new peer is inserted
    /// in the routing table. This prevent cascading bootstrap requests when multiple peers are
    /// inserted into the routing table "at the same time". This also allows to wait a little
    /// bit for other potential peers to be inserted into the routing table before triggering a
    /// bootstrap, giving more context to the future bootstrap request.
    ///
    /// * Default to `500` ms.
    /// * Set to `Some(Duration::ZERO)` to never wait before triggering a bootstrap request when a
    ///   new peer is inserted in the routing table.
    /// * Set to `None` to disable automatic bootstrap (no bootstrap request will be triggered when
    ///   a new peer is inserted in the routing table).
    #[cfg(test)]
    pub(crate) fn set_automatic_bootstrap_throttle(
        &mut self,
        duration: Option<Duration>,
    ) -> &mut Self {
        self.automatic_bootstrap_throttle = duration;
        self
    }
}

impl<TStore> Behaviour<TStore>
where
    TStore: RecordStore + Send + 'static,
{
    /// Creates a new `Kademlia` network behaviour with a default configuration.
    pub fn new(id: PeerId, store: TStore) -> Self {
        Self::with_config(id, store, Default::default())
    }

    /// Get the protocol name of this kademlia instance.
    pub fn protocol_names(&self) -> &[StreamProtocol] {
        self.protocol_config.protocol_names()
    }

    /// Creates a new `Kademlia` network behaviour with the given configuration.
    pub fn with_config(id: PeerId, store: TStore, config: Config) -> Self {
        let local_key = kbucket::Key::from(id);

        let put_record_job = config
            .record_replication_interval
            .or(config.record_publication_interval)
            .map(|interval| {
                PutRecordJob::new(
                    id,
                    interval,
                    config.record_publication_interval,
                    config.record_ttl,
                )
            });

        let add_provider_job = config
            .provider_publication_interval
            .map(AddProviderJob::new);

        Behaviour {
            store,
            caching: config.caching,
            kbuckets: KBucketsTable::new(local_key, config.kbucket_config),
            kbucket_inserts: config.kbucket_inserts,
            protocol_config: config.protocol_config,
            record_filtering: config.record_filtering,
            queued_events: VecDeque::with_capacity(config.query_config.replication_factor.get()),
            listen_addresses: Default::default(),
            queries: QueryPool::new(config.query_config),
            connected_peers: Default::default(),
            add_provider_job,
            put_record_job,
            record_ttl: config.record_ttl,
            provider_record_ttl: config.provider_record_ttl,
            external_addresses: Default::default(),
            local_peer_id: id,
            connections: Default::default(),
            mode: Mode::Client,
            auto_mode: true,
            no_events_waker: None,
            bootstrap_status: bootstrap::Status::new(
                config.periodic_bootstrap_interval,
                config.automatic_bootstrap_throttle,
            ),
        }
    }

    /// Gets an iterator over immutable references to all running queries.
    pub fn iter_queries(&self) -> impl Iterator<Item = QueryRef<'_>> {
        self.queries.iter().filter_map(|query| {
            if !query.is_finished() {
                Some(QueryRef { query })
            } else {
                None
            }
        })
    }

    /// Gets an iterator over mutable references to all running queries.
    pub fn iter_queries_mut(&mut self) -> impl Iterator<Item = QueryMut<'_>> {
        self.queries.iter_mut().filter_map(|query| {
            if !query.is_finished() {
                Some(QueryMut { query })
            } else {
                None
            }
        })
    }

    /// Gets an immutable reference to a running query, if it exists.
    pub fn query(&self, id: &QueryId) -> Option<QueryRef<'_>> {
        self.queries.get(id).and_then(|query| {
            if !query.is_finished() {
                Some(QueryRef { query })
            } else {
                None
            }
        })
    }

    /// Gets a mutable reference to a running query, if it exists.
    pub fn query_mut<'a>(&'a mut self, id: &QueryId) -> Option<QueryMut<'a>> {
        self.queries.get_mut(id).and_then(|query| {
            if !query.is_finished() {
                Some(QueryMut { query })
            } else {
                None
            }
        })
    }

    /// Cancels a running query by removing it from the query pool.
    ///
    /// This immediately stops the query and no further progress events
    /// will be emitted for it.
    ///
    /// Returns `true` if the query was found and cancelled,
    /// `false` if no query with the given ID was found.
    pub fn cancel_query(&mut self, id: &QueryId) -> bool {
        self.queries.remove(id).is_some()
    }

    /// Adds a known listen address of a peer participating in the DHT to the
    /// routing table.
    ///
    /// Explicitly adding addresses of peers serves two purposes:
    ///
    ///   1. In order for a node to join the DHT, it must know about at least one other node of the
    ///      DHT.
    ///
    ///   2. When a remote peer initiates a connection and that peer is not yet in the routing
    ///      table, the `Kademlia` behaviour must be informed of an address on which that peer is
    ///      listening for connections before it can be added to the routing table from where it can
    ///      subsequently be discovered by all peers in the DHT.
    ///
    /// If the routing table has been updated as a result of this operation,
    /// a [`Event::RoutingUpdated`] event is emitted.
    pub fn add_address(&mut self, peer: &PeerId, address: Multiaddr) -> RoutingUpdate {
        // ensuring address is a fully-qualified /p2p multiaddr
        let Ok(address) = address.with_p2p(*peer) else {
            return RoutingUpdate::Failed;
        };
        let key = kbucket::Key::from(*peer);
        match self.kbuckets.entry(&key) {
            Some(kbucket::Entry::Present(mut entry, _)) => {
                if entry.value().insert(address) {
                    self.queued_events
                        .push_back(ToSwarm::GenerateEvent(Event::RoutingUpdated {
                            peer: *peer,
                            is_new_peer: false,
                            addresses: entry.value().clone(),
                            old_peer: None,
                            bucket_range: self
                                .kbuckets
                                .bucket(&key)
                                .map(|b| b.range())
                                .expect("Not kbucket::Entry::SelfEntry."),
                        }))
                }
                RoutingUpdate::Success
            }
            Some(kbucket::Entry::Pending(mut entry, _)) => {
                entry.value().insert(address);
                RoutingUpdate::Pending
            }
            Some(kbucket::Entry::Absent(entry)) => {
                let addresses = Addresses::new(address);
                let status = if self.connected_peers.contains(peer) {
                    NodeStatus::Connected
                } else {
                    NodeStatus::Disconnected
                };
                match entry.insert(addresses.clone(), status) {
                    kbucket::InsertResult::Inserted => {
                        self.bootstrap_on_low_peers();

                        self.queued_events.push_back(ToSwarm::GenerateEvent(
                            Event::RoutingUpdated {
                                peer: *peer,
                                is_new_peer: true,
                                addresses,
                                old_peer: None,
                                bucket_range: self
                                    .kbuckets
                                    .bucket(&key)
                                    .map(|b| b.range())
                                    .expect("Not kbucket::Entry::SelfEntry."),
                            },
                        ));
                        RoutingUpdate::Success
                    }
                    kbucket::InsertResult::Full => {
                        tracing::debug!(%peer, "Bucket full. Peer not added to routing table");
                        RoutingUpdate::Failed
                    }
                    kbucket::InsertResult::Pending { disconnected } => {
                        self.queued_events.push_back(ToSwarm::Dial {
                            opts: DialOpts::peer_id(disconnected.into_preimage()).build(),
                        });
                        RoutingUpdate::Pending
                    }
                }
            }
            None => RoutingUpdate::Failed,
        }
    }

    /// Removes an address of a peer from the routing table.
    ///
    /// If the given address is the last address of the peer in the
    /// routing table, the peer is removed from the routing table
    /// and `Some` is returned with a view of the removed entry.
    /// The same applies if the peer is currently pending insertion
    /// into the routing table.
    ///
    /// If the given peer or address is not in the routing table,
    /// this is a no-op.
    pub fn remove_address(
        &mut self,
        peer: &PeerId,
        address: &Multiaddr,
    ) -> Option<kbucket::EntryView<kbucket::Key<PeerId>, Addresses>> {
        let address = &address.to_owned().with_p2p(*peer).ok()?;
        let key = kbucket::Key::from(*peer);
        match self.kbuckets.entry(&key)? {
            kbucket::Entry::Present(mut entry, _) => {
                if entry.value().remove(address).is_err() {
                    Some(entry.remove()) // it is the last address, thus remove the peer.
                } else {
                    None
                }
            }
            kbucket::Entry::Pending(mut entry, _) => {
                if entry.value().remove(address).is_err() {
                    Some(entry.remove()) // it is the last address, thus remove the peer.
                } else {
                    None
                }
            }
            kbucket::Entry::Absent(..) => None,
        }
    }

    /// Removes a peer from the routing table.
    ///
    /// Returns `None` if the peer was not in the routing table,
    /// not even pending insertion.
    pub fn remove_peer(
        &mut self,
        peer: &PeerId,
    ) -> Option<kbucket::EntryView<kbucket::Key<PeerId>, Addresses>> {
        let key = kbucket::Key::from(*peer);
        match self.kbuckets.entry(&key)? {
            kbucket::Entry::Present(entry, _) => Some(entry.remove()),
            kbucket::Entry::Pending(entry, _) => Some(entry.remove()),
            kbucket::Entry::Absent(..) => None,
        }
    }

    /// Returns an iterator over all non-empty buckets in the routing table.
    pub fn kbuckets(
        &mut self,
    ) -> impl Iterator<Item = kbucket::KBucketRef<'_, kbucket::Key<PeerId>, Addresses>> {
        self.kbuckets.iter().filter(|b| !b.is_empty())
    }

    /// Returns the k-bucket for the distance to the given key.
    ///
    /// Returns `None` if the given key refers to the local key.
    pub fn kbucket<K>(
        &mut self,
        key: K,
    ) -> Option<kbucket::KBucketRef<'_, kbucket::Key<PeerId>, Addresses>>
    where
        K: Into<kbucket::Key<K>> + Clone,
    {
        self.kbuckets.bucket(&key.into())
    }

    /// Initiates an iterative query for the closest peers to the given key.
    ///
    /// The result of the query is delivered in one or more
    /// [`Event::OutboundQueryProgressed`] events with [`QueryResult::GetClosestPeers`].
    ///
    /// # Using with `PeerId`
    ///
    /// This method accepts a [`PeerId`] directly as the key, which can be useful when you
    /// want to discover a specific peer's neighbors or find routes toward a known peer.
    /// However, note that this finds peers *close to* the given key in the DHT keyspace —
    /// the target peer itself will only appear in the results if it is an active participant
    /// in the DHT. For content lookups, use [`Behaviour::get_providers`] or
    /// [`Behaviour::get_record`] instead.
    ///
    /// Addresses discovered during the lookup are automatically cached and provided to the
    /// swarm for dialing.
    pub fn get_closest_peers<K>(&mut self, key: K) -> QueryId
    where
        K: Into<kbucket::Key<K>> + Into<Vec<u8>> + Clone,
    {
        self.get_closest_peers_inner(key, None)
    }

    /// Initiates an iterative query for the closest peers to the given key.
    /// The expected responding peers is specified by `num_results`
    /// Note that the result is capped after exceeds K_VALUE
    ///
    /// The result of the query is delivered in a
    /// [`Event::OutboundQueryProgressed{QueryResult::GetClosestPeers}`].
    pub fn get_n_closest_peers<K>(&mut self, key: K, num_results: NonZeroUsize) -> QueryId
    where
        K: Into<kbucket::Key<K>> + Into<Vec<u8>> + Clone,
    {
        // The inner code never expect higher than K_VALUE results to be returned.
        // And removing such cap will be tricky,
        // since it would involve forging a new key and additional requests.
        // Hence bound to K_VALUE here to set clear expectation and prevent unexpected behaviour.
        let capped_num_results = std::cmp::min(num_results, K_VALUE);
        self.get_closest_peers_inner(key, Some(capped_num_results))
    }

    fn get_closest_peers_inner<K>(&mut self, key: K, num_results: Option<NonZeroUsize>) -> QueryId
    where
        K: Into<kbucket::Key<K>> + Into<Vec<u8>> + Clone,
    {
        let target: kbucket::Key<K> = key.clone().into();
        let key: Vec<u8> = key.into();
        let info = QueryInfo::GetClosestPeers {
            key,
            step: ProgressStep::first(),
            num_results,
        };
        let peer_keys: Vec<kbucket::Key<PeerId>> = self.kbuckets.closest_keys(&target).collect();
        self.queries.add_iter_closest(target, peer_keys, info)
    }

    /// Returns all peers ordered by distance to the given key; takes peers from local routing table
    /// only.
    pub fn get_closest_local_peers<'a, K: Clone>(
        &'a mut self,
        key: &'a kbucket::Key<K>,
    ) -> impl Iterator<Item = kbucket::Key<PeerId>> + 'a {
        self.kbuckets.closest_keys(key)
    }

    /// Finds the closest peers to a `key` in the context of a request by the `source` peer, such
    /// that the `source` peer is never included in the result.
    ///
    /// Takes peers from local routing table only. Only returns number of peers equal to configured
    /// replication factor.
    pub fn find_closest_local_peers<'a, K: Clone>(
        &'a mut self,
        key: &'a kbucket::Key<K>,
        source: &'a PeerId,
    ) -> impl Iterator<Item = KadPeer> + 'a {
        self.kbuckets
            .closest(key)
            .filter(move |e| e.node.key.preimage() != source)
            .take(self.queries.config().replication_factor.get())
            .map(KadPeer::from)
    }

    /// Performs a lookup for a record in the DHT.
    ///
    /// The result of this operation is delivered in a
    /// [`Event::OutboundQueryProgressed{QueryResult::GetRecord}`].
    pub fn get_record(&mut self, key: record::Key) -> QueryId {
        let record = if let Some(record) = self.store.get(&key) {
            if record.is_expired(Instant::now()) {
                self.store.remove(&key);
                None
            } else {
                Some(PeerRecord {
                    peer: None,
                    record: record.into_owned(),
                })
            }
        } else {
            None
        };

        let step = ProgressStep::first();

        let target = kbucket::Key::new(key.clone());
        let info = if record.is_some() {
            QueryInfo::GetRecord {
                key,
                step: step.next(),
                found_a_record: true,
                cache_candidates: BTreeMap::new(),
            }
        } else {
            QueryInfo::GetRecord {
                key,
                step: step.clone(),
                found_a_record: false,
                cache_candidates: BTreeMap::new(),
            }
        };
        let peers = self.kbuckets.closest_keys(&target);
        let id = self.queries.add_iter_closest(target.clone(), peers, info);

        // No queries were actually done for the results yet.
        let stats = QueryStats::empty();

        if let Some(record) = record {
            self.queued_events
                .push_back(ToSwarm::GenerateEvent(Event::OutboundQueryProgressed {
                    id,
                    result: QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(record))),
                    step,
                    stats,
                }));
        }

        id
    }

    /// Stores a record in the DHT, locally as well as at the nodes
    /// closest to the key as per the xor distance metric.
    ///
    /// Returns `Ok` if a record has been stored locally, providing the
    /// `QueryId` of the initial query that replicates the record in the DHT.
    /// The result of the query is eventually reported as a
    /// [`Event::OutboundQueryProgressed{QueryResult::PutRecord}`].
    ///
    /// The record is always stored locally with the given expiration. If the record's
    /// expiration is `None`, the common case, it does not expire in local storage
    /// but is still replicated with the configured record TTL. To remove the record
    /// locally and stop it from being re-published in the DHT, see [`Behaviour::remove_record`].
    ///
    /// After the initial publication of the record, it is subject to (re-)replication
    /// and (re-)publication as per the configured intervals. Periodic (re-)publication
    /// does not update the record's expiration in local storage, thus a given record
    /// with an explicit expiration will always expire at that instant and until then
    /// is subject to regular (re-)replication and (re-)publication.
    pub fn put_record(
        &mut self,
        mut record: Record,
        quorum: Quorum,
    ) -> Result<QueryId, store::Error> {
        record.publisher = Some(*self.kbuckets.local_key().preimage());
        self.store.put(record.clone())?;
        record.expires = record
            .expires
            .or_else(|| self.record_ttl.map(|ttl| Instant::now() + ttl));
        let quorum = quorum.eval(self.queries.config().replication_factor);
        let target = kbucket::Key::new(record.key.clone());
        let peers = self.kbuckets.closest_keys(&target);
        let context = PutRecordContext::Publish;
        let info = QueryInfo::PutRecord {
            context,
            record,
            quorum,
            phase: PutRecordPhase::GetClosestPeers,
        };
        Ok(self.queries.add_iter_closest(target.clone(), peers, info))
    }

    /// Stores a record at specific peers, without storing it locally.
    ///
    /// The given [`Quorum`] is understood in the context of the total
    /// number of distinct peers given.
    ///
    /// If the record's expiration is `None`, the configured record TTL is used.
    ///
    /// > **Note**: This is not a regular Kademlia DHT operation. It needs to be
    /// > used to selectively update or store a record to specific peers
    /// > for the purpose of e.g. making sure these peers have the latest
    /// > "version" of a record or to "cache" a record at further peers
    /// > to increase the lookup success rate on the DHT for other peers.
    /// >
    /// > In particular, there is no automatic storing of records performed, and this
    /// > method must be used to ensure the standard Kademlia
    /// > procedure of "caching" (i.e. storing) a found record at the closest
    /// > node to the key that _did not_ return it.
    pub fn put_record_to<I>(&mut self, mut record: Record, peers: I, quorum: Quorum) -> QueryId
    where
        I: ExactSizeIterator<Item = PeerId>,
    {
        let quorum = if peers.len() > 0 {
            quorum.eval(NonZeroUsize::new(peers.len()).expect("> 0"))
        } else {
            // If no peers are given, we just let the query fail immediately
            // due to the fact that the quorum must be at least one, instead of
            // introducing a new kind of error.
            NonZeroUsize::new(1).expect("1 > 0")
        };
        record.expires = record
            .expires
            .or_else(|| self.record_ttl.map(|ttl| Instant::now() + ttl));
        let context = PutRecordContext::Custom;
        let info = QueryInfo::PutRecord {
            context,
            record,
            quorum,
            phase: PutRecordPhase::PutRecord {
                success: Vec::new(),
                get_closest_peers_stats: QueryStats::empty(),
            },
        };
        self.queries.add_fixed(peers, info)
    }

    /// Removes the record with the given key from _local_ storage,
    /// if the local node is the publisher of the record.
    ///
    /// Has no effect if a record for the given key is stored locally but
    /// the local node is not a publisher of the record.
    ///
    /// This is a _local_ operation. However, it also has the effect that
    /// the record will no longer be periodically re-published, allowing the
    /// record to eventually expire throughout the DHT.
    pub fn remove_record(&mut self, key: &record::Key) {
        if let Some(r) = self.store.get(key) {
            if r.publisher.as_ref() == Some(self.kbuckets.local_key().preimage()) {
                self.store.remove(key)
            }
        }
    }

    /// Gets a mutable reference to the record store.
    pub fn store_mut(&mut self) -> &mut TStore {
        &mut self.store
    }

    /// Bootstraps the local node to join the DHT.
    ///
    /// Bootstrapping is a multi-step operation that starts with a lookup of the local node's
    /// own ID in the DHT. This introduces the local node to the other nodes
    /// in the DHT and populates its routing table with the closest neighbours.
    ///
    /// Subsequently, all buckets farther from the bucket of the closest neighbour are
    /// refreshed by initiating an additional bootstrapping query for each such
    /// bucket with random keys.
    ///
    /// Returns `Ok` if bootstrapping has been initiated with a self-lookup, providing the
    /// `QueryId` for the entire bootstrapping process. The progress of bootstrapping is
    /// reported via [`Event::OutboundQueryProgressed{QueryResult::Bootstrap}`] events,
    /// with one such event per bootstrapping query.
    ///
    /// Returns `Err` if bootstrapping is impossible due an empty routing table.
    ///
    /// > **Note**: Bootstrapping requires at least one node of the DHT to be known.
    /// > See [`Behaviour::add_address`].
    ///
    /// > **Note**: Bootstrap does not require to be called manually. It is periodically
    /// > invoked at regular intervals based on the configured `periodic_bootstrap_interval` (see
    /// > [`Config::set_periodic_bootstrap_interval`] for details) and it is also automatically
    /// > invoked
    /// > when a new peer is inserted in the routing table.
    /// > This parameter is used to call [`Behaviour::bootstrap`] periodically and automatically
    /// > to ensure a healthy routing table.
    pub fn bootstrap(&mut self) -> Result<QueryId, NoKnownPeers> {
        let local_key = *self.kbuckets.local_key();
        let info = QueryInfo::Bootstrap {
            peer: *local_key.preimage(),
            remaining: None,
            step: ProgressStep::first(),
        };
        let peers = self.kbuckets.closest_keys(&local_key).collect::<Vec<_>>();
        if peers.is_empty() {
            self.bootstrap_status.reset_timers();
            Err(NoKnownPeers())
        } else {
            self.bootstrap_status.on_started();
            Ok(self.queries.add_iter_closest(local_key, peers, info))
        }
    }

    /// Establishes the local node as a provider of a value for the given key.
    ///
    /// This operation publishes a provider record with the given key and
    /// identity of the local node to the peers closest to the key, thus establishing
    /// the local node as a provider.
    ///
    /// Returns `Ok` if a provider record has been stored locally, providing the
    /// `QueryId` of the initial query that announces the local node as a provider.
    ///
    /// The publication of the provider records is periodically repeated as per the
    /// configured interval, to renew the expiry and account for changes to the DHT
    /// topology. A provider record may be removed from local storage and
    /// thus no longer re-published by calling [`Behaviour::stop_providing`].
    ///
    /// In contrast to the standard Kademlia push-based model for content distribution
    /// implemented by [`Behaviour::put_record`], the provider API implements a
    /// pull-based model that may be used in addition or as an alternative.
    /// The means by which the actual value is obtained from a provider is out of scope
    /// of the libp2p Kademlia provider API.
    ///
    /// The results of the (repeated) provider announcements sent by this node are
    /// reported via [`Event::OutboundQueryProgressed{QueryResult::StartProviding}`].
    pub fn start_providing(&mut self, key: record::Key) -> Result<QueryId, store::Error> {
        // Note: We store our own provider records locally without local addresses
        // to avoid redundant storage and outdated addresses. Instead these are
        // acquired on demand when returning a `ProviderRecord` for the local node.
        let local_addrs = Vec::new();
        let record = ProviderRecord::new(
            key.clone(),
            *self.kbuckets.local_key().preimage(),
            local_addrs,
        );
        self.store.add_provider(record)?;
        let target = kbucket::Key::new(key.clone());
        let peers = self.kbuckets.closest_keys(&target);
        let context = AddProviderContext::Publish;
        let info = QueryInfo::AddProvider {
            context,
            key,
            phase: AddProviderPhase::GetClosestPeers,
        };
        let id = self.queries.add_iter_closest(target.clone(), peers, info);
        Ok(id)
    }

    /// Stops the local node from announcing that it is a provider for the given key.
    ///
    /// This is a local operation. The local node will still be considered as a
    /// provider for the key by other nodes until these provider records expire.
    pub fn stop_providing(&mut self, key: &record::Key) {
        self.store
            .remove_provider(key, self.kbuckets.local_key().preimage());
    }

    /// Performs a lookup for providers of a value to the given key.
    ///
    /// The result of this operation is delivered via one or more
    /// [`Event::OutboundQueryProgressed`] events with [`QueryResult::GetProviders`].
    ///
    /// The returned provider [`PeerId`]s can be dialed directly — Kademlia automatically
    /// caches the addresses of peers encountered during the lookup and provides them to the
    /// swarm. See [`GetProvidersOk::FoundProviders`] for details.
    pub fn get_providers(&mut self, key: record::Key) -> QueryId {
        let providers: HashMap<_, _> = self
            .store
            .providers(&key)
            .into_iter()
            .filter(|p| !p.is_expired(Instant::now()))
            .map(|p| (p.provider, p.addresses))
            .collect();

        let step = ProgressStep::first();

        let info = QueryInfo::GetProviders {
            key: key.clone(),
            providers_found: providers.len(),
            step: if providers.is_empty() {
                step.clone()
            } else {
                step.next()
            },
        };

        let target = kbucket::Key::new(key.clone());
        let peers = self.kbuckets.closest_keys(&target);
        let id = self.queries.add_iter_closest(target.clone(), peers, info);

        // No queries were actually done for the results yet.
        let stats = QueryStats::empty();

        if !providers.is_empty() {
            self.queued_events
                .push_back(ToSwarm::GenerateEvent(Event::OutboundQueryProgressed {
                    id,
                    result: QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders {
                        key,
                        providers,
                    })),
                    step,
                    stats,
                }));
        }
        id
    }

    /// Set the [`Mode`] in which we should operate.
    ///
    /// By default, we are in [`Mode::Client`] and will swap into [`Mode::Server`] as soon as we
    /// have a confirmed, external address via [`FromSwarm::ExternalAddrConfirmed`].
    ///
    /// Setting a mode via this function disables this automatic behaviour and unconditionally
    /// operates in the specified mode. To reactivate the automatic configuration, pass [`None`]
    /// instead.
    pub fn set_mode(&mut self, mode: Option<Mode>) {
        match mode {
            Some(mode) => {
                self.mode = mode;
                self.auto_mode = false;
                self.reconfigure_mode();
            }
            None => {
                self.auto_mode = true;
                self.determine_mode_from_external_addresses();
            }
        }

        if let Some(waker) = self.no_events_waker.take() {
            waker.wake();
        }
    }

    /// Get the [`Mode`] in which the DHT is currently operating.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    fn reconfigure_mode(&mut self) {
        if self.connections.is_empty() {
            return;
        }

        let num_connections = self.connections.len();

        tracing::debug!(
            "Re-configuring {} established connection{}",
            num_connections,
            if num_connections > 1 { "s" } else { "" }
        );

        self.queued_events
            .extend(
                self.connections
                    .iter()
                    .map(|(conn_id, peer_id)| ToSwarm::NotifyHandler {
                        peer_id: *peer_id,
                        handler: NotifyHandler::One(*conn_id),
                        event: HandlerIn::ReconfigureMode {
                            new_mode: self.mode,
                        },
                    }),
            );
    }

    fn determine_mode_from_external_addresses(&mut self) {
        let old_mode = self.mode;

        self.mode = match (self.external_addresses.as_slice(), self.mode) {
            ([], Mode::Server) => {
                tracing::debug!("Switching to client-mode because we no longer have any confirmed external addresses");

                Mode::Client
            }
            ([], Mode::Client) => {
                // Previously client-mode, now also client-mode because no external addresses.

                Mode::Client
            }
            (confirmed_external_addresses, Mode::Client) => {
                if tracing::enabled!(Level::DEBUG) {
                    let confirmed_external_addresses =
                        to_comma_separated_list(confirmed_external_addresses);

                    tracing::debug!("Switching to server-mode assuming that one of [{confirmed_external_addresses}] is externally reachable");
                }

                Mode::Server
            }
            (confirmed_external_addresses, Mode::Server) => {
                debug_assert!(
                    !confirmed_external_addresses.is_empty(),
                    "Previous match arm handled empty list"
                );

                // Previously, server-mode, now also server-mode because > 1 external address.
                //  Don't log anything to avoid spam.
                Mode::Server
            }
        };

        self.reconfigure_mode();

        if old_mode != self.mode {
            self.queued_events
                .push_back(ToSwarm::GenerateEvent(Event::ModeChanged {
                    new_mode: self.mode,
                }));
        }
    }

    /// Processes discovered peers from a successful request in an iterative `Query`.
    fn discovered<'a, I>(&'a mut self, query_id: &QueryId, source: &PeerId, peers: I)
    where
        I: Iterator<Item = &'a KadPeer> + Clone,
    {
        let local_id = self.kbuckets.local_key().preimage();
        let others_iter = peers.filter(|p| &p.node_id != local_id);
        if let Some(query) = self.queries.get_mut(query_id) {
            tracing::trace!(peer=%source, query=?query_id, "Request to peer in query succeeded");
            for peer in others_iter.clone() {
                tracing::trace!(
                    ?peer,
                    %source,
                    query=?query_id,
                    "Peer reported by source in query"
                );
                let addrs = peer.multiaddrs.iter().cloned().collect();
                query.peers.addresses.insert(peer.node_id, addrs);
            }
            query.on_success(source, others_iter.cloned().map(|kp| kp.node_id))
        }
    }

    /// Collects all peers who are known to be providers of the value for a given `Multihash`.
    fn provider_peers(&mut self, key: &record::Key, source: &PeerId) -> Vec<KadPeer> {
        let kbuckets = &mut self.kbuckets;
        let connected = &mut self.connected_peers;
        let listen_addresses = &self.listen_addresses;
        let external_addresses = &self.external_addresses;

        self.store
            .providers(key)
            .into_iter()
            .filter_map(move |p| {
                if &p.provider != source {
                    let node_id = p.provider;
                    let multiaddrs = p.addresses;
                    let connection_ty = if connected.contains(&node_id) {
                        ConnectionType::Connected
                    } else {
                        ConnectionType::NotConnected
                    };
                    if multiaddrs.is_empty() {
                        // The provider is either the local node and we fill in
                        // the local addresses on demand, or it is a legacy
                        // provider record without addresses, in which case we
                        // try to find addresses in the routing table, as was
                        // done before provider records were stored along with
                        // their addresses.
                        if &node_id == kbuckets.local_key().preimage() {
                            Some(
                                listen_addresses
                                    .iter()
                                    .chain(external_addresses.iter())
                                    .cloned()
                                    .collect::<Vec<_>>(),
                            )
                        } else {
                            let key = kbucket::Key::from(node_id);
                            kbuckets
                                .entry(&key)
                                .as_mut()
                                .and_then(|e| e.view())
                                .map(|e| e.node.value.clone().into_vec())
                        }
                    } else {
                        Some(multiaddrs)
                    }
                    .map(|multiaddrs| KadPeer {
                        node_id,
                        multiaddrs,
                        connection_ty,
                    })
                } else {
                    None
                }
            })
            .take(self.queries.config().replication_factor.get())
            .collect()
    }

    /// Starts an iterative `ADD_PROVIDER` query for the given key.
    fn start_add_provider(&mut self, key: record::Key, context: AddProviderContext) {
        let info = QueryInfo::AddProvider {
            context,
            key: key.clone(),
            phase: AddProviderPhase::GetClosestPeers,
        };
        let target = kbucket::Key::new(key);
        let peers = self.kbuckets.closest_keys(&target);
        self.queries.add_iter_closest(target.clone(), peers, info);
    }

    /// Starts an iterative `PUT_VALUE` query for the given record.
    fn start_put_record(&mut self, record: Record, quorum: Quorum, context: PutRecordContext) {
        let quorum = quorum.eval(self.queries.config().replication_factor);
        let target = kbucket::Key::new(record.key.clone());
        let peers = self.kbuckets.closest_keys(&target);
        let info = QueryInfo::PutRecord {
            record,
            quorum,
            context,
            phase: PutRecordPhase::GetClosestPeers,
        };
        self.queries.add_iter_closest(target.clone(), peers, info);
    }

    /// Updates the routing table with a new connection status and address of a peer.
    fn connection_updated(
        &mut self,
        peer: PeerId,
        address: Option<Multiaddr>,
        new_status: NodeStatus,
    ) {
        let key = kbucket::Key::from(peer);
        match self.kbuckets.entry(&key) {
            Some(kbucket::Entry::Present(mut entry, old_status)) => {
                if old_status != new_status {
                    entry.update(new_status)
                }
                if let Some(address) = address {
                    if entry.value().insert(address) {
                        self.queued_events.push_back(ToSwarm::GenerateEvent(
                            Event::RoutingUpdated {
                                peer,
                                is_new_peer: false,
                                addresses: entry.value().clone(),
                                old_peer: None,
                                bucket_range: self
                                    .kbuckets
                                    .bucket(&key)
                                    .map(|b| b.range())
                                    .expect("Not kbucket::Entry::SelfEntry."),
                            },
                        ))
                    }
                }
            }

            Some(kbucket::Entry::Pending(mut entry, old_status)) => {
                if let Some(address) = address {
                    entry.value().insert(address);
                }
                if old_status != new_status {
                    entry.update(new_status);
                }
            }

            Some(kbucket::Entry::Absent(entry)) => {
                // Only connected nodes with a known address are newly inserted.
                if new_status != NodeStatus::Connected {
                    return;
                }
                match (address, self.kbucket_inserts) {
                    (None, _) => {
                        self.queued_events
                            .push_back(ToSwarm::GenerateEvent(Event::UnroutablePeer { peer }));
                    }
                    (Some(a), BucketInserts::Manual) => {
                        self.queued_events
                            .push_back(ToSwarm::GenerateEvent(Event::RoutablePeer {
                                peer,
                                address: a,
                            }));
                    }
                    (Some(a), BucketInserts::OnConnected) => {
                        let addresses = Addresses::new(a);
                        match entry.insert(addresses.clone(), new_status) {
                            kbucket::InsertResult::Inserted => {
                                self.bootstrap_on_low_peers();

                                let event = Event::RoutingUpdated {
                                    peer,
                                    is_new_peer: true,
                                    addresses,
                                    old_peer: None,
                                    bucket_range: self
                                        .kbuckets
                                        .bucket(&key)
                                        .map(|b| b.range())
                                        .expect("Not kbucket::Entry::SelfEntry."),
                                };
                                self.queued_events.push_back(ToSwarm::GenerateEvent(event));
                            }
                            kbucket::InsertResult::Full => {
                                tracing::debug!(
                                    %peer,
                                    "Bucket full. Peer not added to routing table"
                                );
                                let address = addresses.first().clone();
                                self.queued_events.push_back(ToSwarm::GenerateEvent(
                                    Event::RoutablePeer { peer, address },
                                ));
                            }
                            kbucket::InsertResult::Pending { disconnected } => {
                                let address = addresses.first().clone();
                                self.queued_events.push_back(ToSwarm::GenerateEvent(
                                    Event::PendingRoutablePeer { peer, address },
                                ));

                                // `disconnected` might already be in the process of re-connecting.
                                // In other words `disconnected` might have already re-connected but
                                // is not yet confirmed to support the Kademlia protocol via
                                // [`HandlerEvent::ProtocolConfirmed`].
                                //
                                // Only try dialing peer if not currently connected.
                                if !self.connected_peers.contains(disconnected.preimage()) {
                                    self.queued_events.push_back(ToSwarm::Dial {
                                        opts: DialOpts::peer_id(disconnected.into_preimage())
                                            .build(),
                                    })
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// A new peer has been inserted in the routing table but we check if the routing
    /// table is currently small (less that `K_VALUE` peers are present) and only
    /// trigger a bootstrap in that case
    fn bootstrap_on_low_peers(&mut self) {
        if self
            .kbuckets()
            .map(|kbucket| kbucket.num_entries())
            .sum::<usize>()
            < K_VALUE.get()
        {
            self.bootstrap_status.trigger();
        }
    }

    /// Handles a finished (i.e. successful) query.
    fn query_finished(&mut self, q: Query) -> Option<Event> {
        let query_id = q.id();
        tracing::trace!(query=?query_id, "Query finished");
        match q.info {
            QueryInfo::Bootstrap {
                peer,
                remaining,
                mut step,
            } => {
                let local_key = *self.kbuckets.local_key();
                let mut remaining = remaining.unwrap_or_else(|| {
                    debug_assert_eq!(&peer, local_key.preimage());
                    // The lookup for the local key finished. To complete the bootstrap process,
                    // a bucket refresh should be performed for every bucket farther away than
                    // the first non-empty bucket (which are most likely no more than the last
                    // few, i.e. farthest, buckets).
                    self.kbuckets
                        .iter()
                        .skip_while(|b| b.is_empty())
                        .skip(1) // Skip the bucket with the closest neighbour.
                        .map(|b| {
                            // Try to find a key that falls into the bucket. While such keys can
                            // be generated fully deterministically, the current libp2p kademlia
                            // wire protocol requires transmission of the preimages of the actual
                            // keys in the DHT keyspace, hence for now this is just a "best effort"
                            // to find a key that hashes into a specific bucket. The probabilities
                            // of finding a key in the bucket `b` with as most 16 trials are as
                            // follows:
                            //
                            // Pr(bucket-255) = 1 - (1/2)^16   ~= 1
                            // Pr(bucket-254) = 1 - (3/4)^16   ~= 1
                            // Pr(bucket-253) = 1 - (7/8)^16   ~= 0.88
                            // Pr(bucket-252) = 1 - (15/16)^16 ~= 0.64
                            // ...
                            let mut target = kbucket::Key::from(PeerId::random());
                            for _ in 0..16 {
                                let d = local_key.distance(&target);
                                if b.contains(&d) {
                                    break;
                                }
                                target = kbucket::Key::from(PeerId::random());
                            }
                            target
                        })
                        .collect::<Vec<_>>()
                        .into_iter()
                });

                let num_remaining = remaining.len() as u32;

                if let Some(target) = remaining.next() {
                    let info = QueryInfo::Bootstrap {
                        peer: *target.preimage(),
                        remaining: Some(remaining),
                        step: step.next(),
                    };
                    let peers = self.kbuckets.closest_keys(&target);
                    self.queries
                        .continue_iter_closest(query_id, target, peers, info);
                } else {
                    step.last = true;
                    self.bootstrap_status.on_finish();
                };

                Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: q.stats,
                    result: QueryResult::Bootstrap(Ok(BootstrapOk {
                        peer,
                        num_remaining,
                    })),
                    step,
                })
            }

            QueryInfo::GetClosestPeers { key, mut step, .. } => {
                step.last = true;

                Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: q.stats,
                    result: QueryResult::GetClosestPeers(Ok(GetClosestPeersOk {
                        key,
                        peers: q.peers.into_peerinfos_iter().collect(),
                    })),
                    step,
                })
            }

            QueryInfo::GetProviders { mut step, .. } => {
                step.last = true;

                Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: q.stats,
                    result: QueryResult::GetProviders(Ok(
                        GetProvidersOk::FinishedWithNoAdditionalRecord {
                            closest_peers: q.peers.into_peerids_iter().collect(),
                        },
                    )),
                    step,
                })
            }

            QueryInfo::AddProvider {
                context,
                key,
                phase: AddProviderPhase::GetClosestPeers,
            } => {
                let provider_id = self.local_peer_id;
                let external_addresses = self.external_addresses.iter().cloned().collect();
                let info = QueryInfo::AddProvider {
                    context,
                    key,
                    phase: AddProviderPhase::AddProvider {
                        provider_id,
                        external_addresses,
                        get_closest_peers_stats: q.stats,
                    },
                };
                self.queries
                    .continue_fixed(query_id, q.peers.into_peerids_iter(), info);
                None
            }

            QueryInfo::AddProvider {
                context,
                key,
                phase:
                    AddProviderPhase::AddProvider {
                        get_closest_peers_stats,
                        ..
                    },
            } => match context {
                AddProviderContext::Publish => Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: get_closest_peers_stats.merge(q.stats),
                    result: QueryResult::StartProviding(Ok(AddProviderOk { key })),
                    step: ProgressStep::first_and_last(),
                }),
                AddProviderContext::Republish => Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: get_closest_peers_stats.merge(q.stats),
                    result: QueryResult::RepublishProvider(Ok(AddProviderOk { key })),
                    step: ProgressStep::first_and_last(),
                }),
            },

            QueryInfo::GetRecord {
                key,
                mut step,
                found_a_record,
                cache_candidates,
            } => {
                step.last = true;

                let results = if found_a_record {
                    Ok(GetRecordOk::FinishedWithNoAdditionalRecord { cache_candidates })
                } else {
                    Err(GetRecordError::NotFound {
                        key,
                        closest_peers: q.peers.into_peerids_iter().collect(),
                    })
                };
                Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: q.stats,
                    result: QueryResult::GetRecord(results),
                    step,
                })
            }

            QueryInfo::PutRecord {
                context,
                record,
                quorum,
                phase: PutRecordPhase::GetClosestPeers,
            } => {
                let info = QueryInfo::PutRecord {
                    context,
                    record,
                    quorum,
                    phase: PutRecordPhase::PutRecord {
                        success: vec![],
                        get_closest_peers_stats: q.stats,
                    },
                };
                self.queries
                    .continue_fixed(query_id, q.peers.into_peerids_iter(), info);
                None
            }

            QueryInfo::PutRecord {
                context,
                record,
                quorum,
                phase:
                    PutRecordPhase::PutRecord {
                        success,
                        get_closest_peers_stats,
                    },
            } => {
                let mk_result = |key: record::Key| {
                    if success.len() >= quorum.get() {
                        Ok(PutRecordOk { key })
                    } else {
                        Err(PutRecordError::QuorumFailed {
                            key,
                            quorum,
                            success,
                        })
                    }
                };
                match context {
                    PutRecordContext::Publish | PutRecordContext::Custom => {
                        Some(Event::OutboundQueryProgressed {
                            id: query_id,
                            stats: get_closest_peers_stats.merge(q.stats),
                            result: QueryResult::PutRecord(mk_result(record.key)),
                            step: ProgressStep::first_and_last(),
                        })
                    }
                    PutRecordContext::Republish => Some(Event::OutboundQueryProgressed {
                        id: query_id,
                        stats: get_closest_peers_stats.merge(q.stats),
                        result: QueryResult::RepublishRecord(mk_result(record.key)),
                        step: ProgressStep::first_and_last(),
                    }),
                    PutRecordContext::Replicate => {
                        tracing::debug!(record=?record.key, "Record replicated");
                        None
                    }
                }
            }
        }
    }

    /// Handles a query that timed out.
    fn query_timeout(&mut self, query: Query) -> Option<Event> {
        let query_id = query.id();
        tracing::trace!(query=?query_id, "Query timed out");
        match query.info {
            QueryInfo::Bootstrap {
                peer,
                mut remaining,
                mut step,
            } => {
                let num_remaining = remaining.as_ref().map(|r| r.len().saturating_sub(1) as u32);

                // Continue with the next bootstrap query if `remaining` is not empty.
                if let Some((target, remaining)) =
                    remaining.take().and_then(|mut r| Some((r.next()?, r)))
                {
                    let info = QueryInfo::Bootstrap {
                        peer: target.into_preimage(),
                        remaining: Some(remaining),
                        step: step.next(),
                    };
                    let peers = self.kbuckets.closest_keys(&target);
                    self.queries
                        .continue_iter_closest(query_id, target, peers, info);
                } else {
                    step.last = true;
                    self.bootstrap_status.on_finish();
                }

                Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: query.stats,
                    result: QueryResult::Bootstrap(Err(BootstrapError::Timeout {
                        peer,
                        num_remaining,
                    })),
                    step,
                })
            }

            QueryInfo::AddProvider { context, key, .. } => Some(match context {
                AddProviderContext::Publish => Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: query.stats,
                    result: QueryResult::StartProviding(Err(AddProviderError::Timeout { key })),
                    step: ProgressStep::first_and_last(),
                },
                AddProviderContext::Republish => Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: query.stats,
                    result: QueryResult::RepublishProvider(Err(AddProviderError::Timeout { key })),
                    step: ProgressStep::first_and_last(),
                },
            }),

            QueryInfo::GetClosestPeers { key, mut step, .. } => {
                step.last = true;
                Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: query.stats,
                    result: QueryResult::GetClosestPeers(Err(GetClosestPeersError::Timeout {
                        key,
                        peers: query.peers.into_peerinfos_iter().collect(),
                    })),
                    step,
                })
            }

            QueryInfo::PutRecord {
                record,
                quorum,
                context,
                phase,
            } => {
                let err = Err(PutRecordError::Timeout {
                    key: record.key,
                    quorum,
                    success: match phase {
                        PutRecordPhase::GetClosestPeers => vec![],
                        PutRecordPhase::PutRecord { ref success, .. } => success.clone(),
                    },
                });
                match context {
                    PutRecordContext::Publish | PutRecordContext::Custom => {
                        Some(Event::OutboundQueryProgressed {
                            id: query_id,
                            stats: query.stats,
                            result: QueryResult::PutRecord(err),
                            step: ProgressStep::first_and_last(),
                        })
                    }
                    PutRecordContext::Republish => Some(Event::OutboundQueryProgressed {
                        id: query_id,
                        stats: query.stats,
                        result: QueryResult::RepublishRecord(err),
                        step: ProgressStep::first_and_last(),
                    }),
                    PutRecordContext::Replicate => match phase {
                        PutRecordPhase::GetClosestPeers => {
                            tracing::warn!(
                                "Locating closest peers for replication failed: {:?}",
                                err
                            );
                            None
                        }
                        PutRecordPhase::PutRecord { .. } => {
                            tracing::debug!("Replicating record failed: {:?}", err);
                            None
                        }
                    },
                }
            }

            QueryInfo::GetRecord { key, mut step, .. } => {
                step.last = true;

                Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: query.stats,
                    result: QueryResult::GetRecord(Err(GetRecordError::Timeout { key })),
                    step,
                })
            }

            QueryInfo::GetProviders { key, mut step, .. } => {
                step.last = true;

                Some(Event::OutboundQueryProgressed {
                    id: query_id,
                    stats: query.stats,
                    result: QueryResult::GetProviders(Err(GetProvidersError::Timeout {
                        key,
                        closest_peers: query.peers.into_peerids_iter().collect(),
                    })),
                    step,
                })
            }
        }
    }

    /// Processes a record received from a peer.
    fn record_received(
        &mut self,
        source: PeerId,
        connection: ConnectionId,
        request_id: RequestId,
        mut record: Record,
    ) {
        if record.publisher.as_ref() == Some(self.kbuckets.local_key().preimage()) {
            // If the (alleged) publisher is the local node, do nothing. The record of
            // the original publisher should never change as a result of replication
            // and the publisher is always assumed to have the "right" value.
            self.queued_events.push_back(ToSwarm::NotifyHandler {
                peer_id: source,
                handler: NotifyHandler::One(connection),
                event: HandlerIn::PutRecordRes {
                    key: record.key,
                    value: record.value,
                    request_id,
                },
            });
            return;
        }

        let now = Instant::now();

        // Calculate the expiration exponentially inversely proportional to the
        // number of nodes between the local node and the closest node to the key
        // (beyond the replication factor). This ensures avoiding over-caching
        // outside of the k closest nodes to a key.
        let target = kbucket::Key::new(record.key.clone());
        let num_between = self.kbuckets.count_nodes_between(&target);
        let k = self.queries.config().replication_factor.get();
        let num_beyond_k = (usize::max(k, num_between) - k) as u32;
        let expiration = self
            .record_ttl
            .map(|ttl| now + exp_decrease(ttl, num_beyond_k));
        // The smaller TTL prevails. Only if neither TTL is set is the record
        // stored "forever".
        record.expires = record.expires.or(expiration).min(expiration);

        if let Some(job) = self.put_record_job.as_mut() {
            // Ignore the record in the next run of the replication
            // job, since we can assume the sender replicated the
            // record to the k closest peers. Effectively, only
            // one of the k closest peers performs a replication
            // in the configured interval, assuming a shared interval.
            job.skip(record.key.clone())
        }

        // While records received from a publisher, as well as records that do
        // not exist locally should always (attempted to) be stored, there is a
        // choice here w.r.t. the handling of replicated records whose keys refer
        // to records that exist locally: The value and / or the publisher may
        // either be overridden or left unchanged. At the moment and in the
        // absence of a decisive argument for another option, both are always
        // overridden as it avoids having to load the existing record in the
        // first place.

        if !record.is_expired(now) {
            // The record is cloned because of the weird libp2p protocol
            // requirement to send back the value in the response, although this
            // is a waste of resources.
            match self.record_filtering {
                StoreInserts::Unfiltered => match self.store.put(record.clone()) {
                    Ok(()) => {
                        tracing::debug!(
                            record=?record.key,
                            "Record stored: {} bytes",
                            record.value.len()
                        );
                        self.queued_events.push_back(ToSwarm::GenerateEvent(
                            Event::InboundRequest {
                                request: InboundRequest::PutRecord {
                                    source,
                                    connection,
                                    record: None,
                                },
                            },
                        ));
                    }
                    Err(e) => {
                        tracing::info!("Record not stored: {:?}", e);
                        self.queued_events.push_back(ToSwarm::NotifyHandler {
                            peer_id: source,
                            handler: NotifyHandler::One(connection),
                            event: HandlerIn::Reset(request_id),
                        });

                        return;
                    }
                },
                StoreInserts::FilterBoth => {
                    self.queued_events
                        .push_back(ToSwarm::GenerateEvent(Event::InboundRequest {
                            request: InboundRequest::PutRecord {
                                source,
                                connection,
                                record: Some(record.clone()),
                            },
                        }));
                }
            }
        }

        // The remote receives a [`HandlerIn::PutRecordRes`] even in the
        // case where the record is discarded due to being expired. Given that
        // the remote sent the local node a [`HandlerEvent::PutRecord`]
        // request, the remote perceives the local node as one node among the k
        // closest nodes to the target. In addition returning
        // [`HandlerIn::PutRecordRes`] does not reveal any internal
        // information to a possibly malicious remote node.
        self.queued_events.push_back(ToSwarm::NotifyHandler {
            peer_id: source,
            handler: NotifyHandler::One(connection),
            event: HandlerIn::PutRecordRes {
                key: record.key,
                value: record.value,
                request_id,
            },
        })
    }

    /// Processes a provider record received from a peer.
    fn provider_received(&mut self, key: record::Key, provider: KadPeer) {
        if &provider.node_id != self.kbuckets.local_key().preimage() {
            let record = ProviderRecord {
                key,
                provider: provider.node_id,
                expires: self.provider_record_ttl.map(|ttl| Instant::now() + ttl),
                addresses: provider.multiaddrs,
            };
            match self.record_filtering {
                StoreInserts::Unfiltered => {
                    if let Err(e) = self.store.add_provider(record) {
                        tracing::info!("Provider record not stored: {:?}", e);
                        return;
                    }

                    self.queued_events
                        .push_back(ToSwarm::GenerateEvent(Event::InboundRequest {
                            request: InboundRequest::AddProvider { record: None },
                        }));
                }
                StoreInserts::FilterBoth => {
                    self.queued_events
                        .push_back(ToSwarm::GenerateEvent(Event::InboundRequest {
                            request: InboundRequest::AddProvider {
                                record: Some(record),
                            },
                        }));
                }
            }
        }
    }

    fn address_failed(&mut self, peer_id: PeerId, address: &Multiaddr) {
        let key = kbucket::Key::from(peer_id);

        if let Some(addrs) = self.kbuckets.entry(&key).as_mut().and_then(|e| e.value()) {
            // TODO: Ideally, the address should only be removed if the error can
            // be classified as "permanent" but since `err` is currently a borrowed
            // trait object without a `'static` bound, even downcasting for inspection
            // of the error is not possible (and also not truly desirable or ergonomic).
            // The error passed in should rather be a dedicated enum.
            if addrs.remove(address).is_ok() {
                tracing::debug!(
                    peer=%peer_id,
                    %address,
                    "Address removed from peer due to error."
                );
            } else {
                // Despite apparently having no reachable address (any longer),
                // the peer is kept in the routing table with the last address to avoid
                // (temporary) loss of network connectivity to "flush" the routing
                // table. Once in, a peer is only removed from the routing table
                // if it is the least recently connected peer, currently disconnected
                // and is unreachable in the context of another peer pending insertion
                // into the same bucket. This is handled transparently by the
                // `KBucketsTable` and takes effect through `KBucketsTable::take_applied_pending`
                // within `Behaviour::poll`.
                tracing::debug!(
                    peer=%peer_id,
                    %address,
                    "Last remaining address of peer is unreachable."
                );
            }
        }

        for query in self.queries.iter_mut() {
            if let Some(addrs) = query.peers.addresses.get_mut(&peer_id) {
                addrs.retain(|a| a != address);
            }
        }
    }

    fn on_connection_established(
        &mut self,
        ConnectionEstablished {
            peer_id,
            failed_addresses,
            other_established,
            ..
        }: ConnectionEstablished,
    ) {
        for addr in failed_addresses {
            self.address_failed(peer_id, addr);
        }

        // Peer's first connection.
        if other_established == 0 {
            self.connected_peers.insert(peer_id);
        }
    }

    fn on_address_change(
        &mut self,
        AddressChange {
            peer_id: peer,
            old,
            new,
            ..
        }: AddressChange,
    ) {
        let (old, new) = (old.get_remote_address(), new.get_remote_address());

        // Update routing table.
        if let Some(addrs) = self
            .kbuckets
            .entry(&kbucket::Key::from(peer))
            .as_mut()
            .and_then(|e| e.value())
        {
            if addrs.replace(old, new) {
                tracing::debug!(
                    %peer,
                    old_address=%old,
                    new_address=%new,
                    "Old address replaced with new address for peer."
                );
            } else {
                tracing::debug!(
                    %peer,
                    old_address=%old,
                    new_address=%new,
                    "Old address not replaced with new address for peer as old address wasn't present.",
                );
            }
        } else {
            tracing::debug!(
                %peer,
                old_address=%old,
                new_address=%new,
                "Old address not replaced with new address for peer as peer is not present in the \
                 routing table."
            );
        }

        // Update query address cache.
        //
        // Given two connected nodes: local node A and remote node B. Say node B
        // is not in node A's routing table. Additionally node B is part of the
        // `Query::addresses` list of an ongoing query on node A. Say Node
        // B triggers an address change and then disconnects. Later on the
        // earlier mentioned query on node A would like to connect to node B.
        // Without replacing the address in the `Query::addresses` set node
        // A would attempt to dial the old and not the new address.
        //
        // While upholding correctness, iterating through all discovered
        // addresses of a peer in all currently ongoing queries might have a
        // large performance impact. If so, the code below might be worth
        // revisiting.
        for query in self.queries.iter_mut() {
            if let Some(addrs) = query.peers.addresses.get_mut(&peer) {
                for addr in addrs.iter_mut() {
                    if addr == old {
                        *addr = new.clone();
                    }
                }
            }
        }
    }

    fn on_dial_failure(&mut self, DialFailure { peer_id, error, .. }: DialFailure) {
        let Some(peer_id) = peer_id else { return };

        match error {
            DialError::LocalPeerId { .. }
            | DialError::WrongPeerId { .. }
            | DialError::Aborted
            | DialError::Denied { .. }
            | DialError::Transport(_)
            | DialError::NoAddresses => {
                if let DialError::Transport(addresses) = error {
                    for (addr, _) in addresses {
                        self.address_failed(peer_id, addr)
                    }
                }

                for query in self.queries.iter_mut() {
                    query.on_failure(&peer_id);
                }
            }
            DialError::DialPeerConditionFalse(
                dial_opts::PeerCondition::Disconnected
                | dial_opts::PeerCondition::NotDialing
                | dial_opts::PeerCondition::DisconnectedAndNotDialing,
            ) => {
                // We might (still) be connected, or about to be connected, thus do not report the
                // failure to the queries.
            }
            DialError::DialPeerConditionFalse(dial_opts::PeerCondition::Always) => {
                unreachable!("DialPeerCondition::Always can not trigger DialPeerConditionFalse.");
            }
        }
    }

    fn on_connection_closed(
        &mut self,
        ConnectionClosed {
            peer_id,
            remaining_established,
            connection_id,
            ..
        }: ConnectionClosed,
    ) {
        self.connections.remove(&connection_id);

        if remaining_established == 0 {
            for query in self.queries.iter_mut() {
                query.on_failure(&peer_id);
            }
            self.connection_updated(peer_id, None, NodeStatus::Disconnected);
            self.connected_peers.remove(&peer_id);
        }
    }

    /// Preloads a new [`Handler`] with requests that are waiting
    /// to be sent to the newly connected peer.
    fn preload_new_handler(
        &mut self,
        handler: &mut Handler,
        connection_id: ConnectionId,
        peer: PeerId,
    ) {
        self.connections.insert(connection_id, peer);
        // Queue events for sending pending RPCs to the connected peer.
        // There can be only one pending RPC for a particular peer and query per definition.
        for (_peer_id, event) in self.queries.iter_mut().filter_map(|q| {
            q.pending_rpcs
                .iter()
                .position(|(p, _)| p == &peer)
                .map(|p| q.pending_rpcs.remove(p))
        }) {
            handler.on_behaviour_event(event)
        }
    }
}

/// Exponentially decrease the given duration (base 2).
fn exp_decrease(ttl: Duration, exp: u32) -> Duration {
    Duration::from_secs(ttl.as_secs().checked_shr(exp).unwrap_or(0))
}

impl<TStore> NetworkBehaviour for Behaviour<TStore>
where
    TStore: RecordStore + Send + 'static,
{
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let connected_point = ConnectedPoint::Listener {
            local_addr: local_addr.clone(),
            send_back_addr: remote_addr.clone(),
        };

        let mut handler = Handler::new(
            self.protocol_config.clone(),
            connected_point,
            peer,
            self.mode,
        );
        self.preload_new_handler(&mut handler, connection_id, peer);

        Ok(handler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let connected_point = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override,
            port_use,
        };

        let mut handler = Handler::new(
            self.protocol_config.clone(),
            connected_point,
            peer,
            self.mode,
        );
        self.preload_new_handler(&mut handler, connection_id, peer);

        Ok(handler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let peer_id = match maybe_peer {
            None => return Ok(vec![]),
            Some(peer) => peer,
        };

        // We should order addresses from decreasing likelihood of connectivity, so start with
        // the addresses of that peer in the k-buckets.
        let key = kbucket::Key::from(peer_id);
        let mut peer_addrs =
            if let Some(kbucket::Entry::Present(mut entry, _)) = self.kbuckets.entry(&key) {
                let addrs = entry.value().iter().cloned().collect::<Vec<_>>();
                debug_assert!(!addrs.is_empty(), "Empty peer addresses in routing table.");
                addrs
            } else {
                Vec::new()
            };

        // We add to that a temporary list of addresses from the ongoing queries.
        for query in self.queries.iter() {
            if let Some(addrs) = query.peers.addresses.get(&peer_id) {
                peer_addrs.extend(addrs.iter().cloned())
            }
        }

        Ok(peer_addrs)
    }

    fn on_connection_handler_event(
        &mut self,
        source: PeerId,
        connection: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            HandlerEvent::ProtocolConfirmed { endpoint } => {
                debug_assert!(self.connected_peers.contains(&source));
                // The remote's address can only be put into the routing table,
                // and thus shared with other nodes, if the local node is the dialer,
                // since the remote address on an inbound connection may be specific
                // to that connection (e.g. typically the TCP port numbers).
                let address = match endpoint {
                    ConnectedPoint::Dialer { address, .. } => Some(address),
                    ConnectedPoint::Listener { .. } => None,
                };

                self.connection_updated(source, address, NodeStatus::Connected);
            }

            HandlerEvent::ProtocolNotSupported { endpoint } => {
                let address = match endpoint {
                    ConnectedPoint::Dialer { address, .. } => Some(address),
                    ConnectedPoint::Listener { .. } => None,
                };
                self.connection_updated(source, address, NodeStatus::Disconnected);
            }

            HandlerEvent::FindNodeReq { key, request_id } => {
                let closer_peers = self
                    .find_closest_local_peers(&kbucket::Key::new(key), &source)
                    .collect::<Vec<_>>();

                self.queued_events
                    .push_back(ToSwarm::GenerateEvent(Event::InboundRequest {
                        request: InboundRequest::FindNode {
                            num_closer_peers: closer_peers.len(),
                        },
                    }));

                self.queued_events.push_back(ToSwarm::NotifyHandler {
                    peer_id: source,
                    handler: NotifyHandler::One(connection),
                    event: HandlerIn::FindNodeRes {
                        closer_peers,
                        request_id,
                    },
                });
            }

            HandlerEvent::FindNodeRes {
                closer_peers,
                query_id,
            } => {
                self.discovered(&query_id, &source, closer_peers.iter());
            }

            HandlerEvent::GetProvidersReq { key, request_id } => {
                let provider_peers = self.provider_peers(&key, &source);
                let closer_peers = self
                    .find_closest_local_peers(&kbucket::Key::new(key), &source)
                    .collect::<Vec<_>>();

                self.queued_events
                    .push_back(ToSwarm::GenerateEvent(Event::InboundRequest {
                        request: InboundRequest::GetProvider {
                            num_closer_peers: closer_peers.len(),
                            num_provider_peers: provider_peers.len(),
                        },
                    }));

                self.queued_events.push_back(ToSwarm::NotifyHandler {
                    peer_id: source,
                    handler: NotifyHandler::One(connection),
                    event: HandlerIn::GetProvidersRes {
                        closer_peers,
                        provider_peers,
                        request_id,
                    },
                });
            }

            HandlerEvent::GetProvidersRes {
                closer_peers,
                provider_peers,
                query_id,
            } => {
                let peers = closer_peers.iter().chain(provider_peers.iter());
                self.discovered(&query_id, &source, peers);
                if let Some(query) = self.queries.get_mut(&query_id) {
                    let stats = query.stats().clone();
                    if let QueryInfo::GetProviders {
                        ref key,
                        ref mut providers_found,
                        ref mut step,
                        ..
                    } = query.info
                    {
                        *providers_found += provider_peers.len();
                        let providers = provider_peers
                            .iter()
                            .map(|p| (p.node_id, p.multiaddrs.clone()))
                            .collect();

                        self.queued_events.push_back(ToSwarm::GenerateEvent(
                            Event::OutboundQueryProgressed {
                                id: query_id,
                                result: QueryResult::GetProviders(Ok(
                                    GetProvidersOk::FoundProviders {
                                        key: key.clone(),
                                        providers,
                                    },
                                )),
                                step: step.clone(),
                                stats,
                            },
                        ));
                        *step = step.next();
                    }
                }
            }
            HandlerEvent::QueryError { query_id, error } => {
                tracing::debug!(
                    peer=%source,
                    query=?query_id,
                    "Request to peer in query failed with {:?}",
                    error
                );
                // If the query to which the error relates is still active,
                // signal the failure w.r.t. `source`.
                if let Some(query) = self.queries.get_mut(&query_id) {
                    query.on_failure(&source)
                }
            }

            HandlerEvent::AddProvider { key, provider } => {
                // Only accept a provider record from a legitimate peer.
                if provider.node_id != source {
                    return;
                }

                self.provider_received(key, provider);
            }

            HandlerEvent::GetRecord { key, request_id } => {
                // Lookup the record locally.
                let record = match self.store.get(&key) {
                    Some(record) => {
                        if record.is_expired(Instant::now()) {
                            self.store.remove(&key);
                            None
                        } else {
                            Some(record.into_owned())
                        }
                    }
                    None => None,
                };

                let closer_peers = self
                    .find_closest_local_peers(&kbucket::Key::new(key), &source)
                    .collect::<Vec<_>>();

                self.queued_events
                    .push_back(ToSwarm::GenerateEvent(Event::InboundRequest {
                        request: InboundRequest::GetRecord {
                            num_closer_peers: closer_peers.len(),
                            present_locally: record.is_some(),
                        },
                    }));

                self.queued_events.push_back(ToSwarm::NotifyHandler {
                    peer_id: source,
                    handler: NotifyHandler::One(connection),
                    event: HandlerIn::GetRecordRes {
                        record,
                        closer_peers,
                        request_id,
                    },
                });
            }

            HandlerEvent::GetRecordRes {
                record,
                closer_peers,
                query_id,
            } => {
                if let Some(query) = self.queries.get_mut(&query_id) {
                    let stats = query.stats().clone();
                    if let QueryInfo::GetRecord {
                        key,
                        ref mut step,
                        ref mut found_a_record,
                        cache_candidates,
                    } = &mut query.info
                    {
                        if let Some(record) = record {
                            *found_a_record = true;
                            let record = PeerRecord {
                                peer: Some(source),
                                record,
                            };

                            self.queued_events.push_back(ToSwarm::GenerateEvent(
                                Event::OutboundQueryProgressed {
                                    id: query_id,
                                    result: QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(
                                        record,
                                    ))),
                                    step: step.clone(),
                                    stats,
                                },
                            ));

                            *step = step.next();
                        } else {
                            tracing::trace!(record=?key, %source, "Record not found at source");
                            if let Caching::Enabled { max_peers } = self.caching {
                                let source_key = kbucket::Key::from(source);
                                let target_key = kbucket::Key::from(key.clone());
                                let distance = source_key.distance(&target_key);
                                cache_candidates.insert(distance, source);
                                if cache_candidates.len() > max_peers as usize {
                                    // TODO: `pop_last()` would be nice once stabilised.
                                    // See https://github.com/rust-lang/rust/issues/62924.
                                    let last =
                                        *cache_candidates.keys().next_back().expect("len > 0");
                                    cache_candidates.remove(&last);
                                }
                            }
                        }
                    }
                }

                self.discovered(&query_id, &source, closer_peers.iter());
            }

            HandlerEvent::PutRecord { record, request_id } => {
                self.record_received(source, connection, request_id, record);
            }

            HandlerEvent::PutRecordRes { query_id, .. } => {
                if let Some(query) = self.queries.get_mut(&query_id) {
                    query.on_success(&source, vec![]);
                    if let QueryInfo::PutRecord {
                        phase: PutRecordPhase::PutRecord { success, .. },
                        quorum,
                        ..
                    } = &mut query.info
                    {
                        success.push(source);

                        let quorum = quorum.get();
                        if success.len() >= quorum {
                            let peers = success.clone();
                            let finished = query.try_finish(peers.iter());
                            if !finished {
                                tracing::debug!(
                                    peer=%source,
                                    query=?query_id,
                                    "PutRecord query reached quorum ({}/{}) with response \
                                     from peer but could not yet finish.",
                                    peers.len(),
                                    quorum,
                                );
                            }
                        }
                    }
                }
            }
        };
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        let now = Instant::now();

        // Calculate the available capacity for queries triggered by background jobs.
        let mut jobs_query_capacity = JOBS_MAX_QUERIES.saturating_sub(self.queries.size());

        // Run the periodic provider announcement job.
        if let Some(mut job) = self.add_provider_job.take() {
            let num = usize::min(JOBS_MAX_NEW_QUERIES, jobs_query_capacity);
            for i in 0..num {
                if let Poll::Ready(r) = job.poll(cx, &mut self.store, now) {
                    self.start_add_provider(r.key, AddProviderContext::Republish)
                } else {
                    jobs_query_capacity -= i;
                    break;
                }
            }
            self.add_provider_job = Some(job);
        }

        // Run the periodic record replication / publication job.
        if let Some(mut job) = self.put_record_job.take() {
            let num = usize::min(JOBS_MAX_NEW_QUERIES, jobs_query_capacity);
            for _ in 0..num {
                if let Poll::Ready(r) = job.poll(cx, &mut self.store, now) {
                    let context =
                        if r.publisher.as_ref() == Some(self.kbuckets.local_key().preimage()) {
                            PutRecordContext::Republish
                        } else {
                            PutRecordContext::Replicate
                        };
                    self.start_put_record(r, Quorum::All, context)
                } else {
                    break;
                }
            }
            self.put_record_job = Some(job);
        }

        // Poll bootstrap periodically and automatically.
        if let Poll::Ready(()) = self.bootstrap_status.poll_next_bootstrap(cx) {
            if let Err(e) = self.bootstrap() {
                tracing::warn!("Failed to trigger bootstrap: {e}");
            }
        }

        loop {
            // Drain queued events first.
            if let Some(event) = self.queued_events.pop_front() {
                return Poll::Ready(event);
            }

            // Drain applied pending entries from the routing table.
            if let Some(entry) = self.kbuckets.take_applied_pending() {
                let kbucket::Node { key, value } = entry.inserted;
                let peer_id = key.into_preimage();
                self.queued_events
                    .push_back(ToSwarm::NewExternalAddrOfPeer {
                        peer_id,
                        address: value.first().clone(),
                    });
                let event = Event::RoutingUpdated {
                    bucket_range: self
                        .kbuckets
                        .bucket(&key)
                        .map(|b| b.range())
                        .expect("Self to never be applied from pending."),
                    peer: peer_id,
                    is_new_peer: true,
                    addresses: value,
                    old_peer: entry.evicted.map(|n| n.key.into_preimage()),
                };
                return Poll::Ready(ToSwarm::GenerateEvent(event));
            }

            // Look for a finished query.
            loop {
                match self.queries.poll(now) {
                    QueryPoolState::Finished(q) => {
                        if let Some(event) = self.query_finished(q) {
                            return Poll::Ready(ToSwarm::GenerateEvent(event));
                        }
                    }
                    QueryPoolState::Timeout(q) => {
                        if let Some(event) = self.query_timeout(q) {
                            return Poll::Ready(ToSwarm::GenerateEvent(event));
                        }
                    }
                    QueryPoolState::Waiting(Some((query, peer_id))) => {
                        let event = query.info.to_request(query.id());
                        // TODO: AddProvider requests yield no response, so the query completes
                        // as soon as all requests have been sent. However, the handler should
                        // better emit an event when the request has been sent (and report
                        // an error if sending fails), instead of immediately reporting
                        // "success" somewhat prematurely here.
                        if let QueryInfo::AddProvider {
                            phase: AddProviderPhase::AddProvider { .. },
                            ..
                        } = &query.info
                        {
                            query.on_success(&peer_id, vec![])
                        }

                        if self.connected_peers.contains(&peer_id) {
                            self.queued_events.push_back(ToSwarm::NotifyHandler {
                                peer_id,
                                event,
                                handler: NotifyHandler::Any,
                            });
                        } else if &peer_id != self.kbuckets.local_key().preimage() {
                            query.pending_rpcs.push((peer_id, event));
                            self.queued_events.push_back(ToSwarm::Dial {
                                opts: DialOpts::peer_id(peer_id).build(),
                            });
                        }
                    }
                    QueryPoolState::Waiting(None) | QueryPoolState::Idle => break,
                }
            }

            // No immediate event was produced as a result of a finished query.
            // If no new events have been queued either, signal `NotReady` to
            // be polled again later.
            if self.queued_events.is_empty() {
                self.no_events_waker = Some(cx.waker().clone());

                return Poll::Pending;
            }
        }
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.listen_addresses.on_swarm_event(&event);
        let external_addresses_changed = self.external_addresses.on_swarm_event(&event);

        if self.auto_mode && external_addresses_changed {
            self.determine_mode_from_external_addresses();
        }

        match event {
            FromSwarm::ConnectionEstablished(connection_established) => {
                self.on_connection_established(connection_established)
            }
            FromSwarm::ConnectionClosed(connection_closed) => {
                self.on_connection_closed(connection_closed)
            }
            FromSwarm::DialFailure(dial_failure) => self.on_dial_failure(dial_failure),
            FromSwarm::AddressChange(address_change) => self.on_address_change(address_change),
            FromSwarm::NewListenAddr(_) if self.connected_peers.is_empty() => {
                // A new listen addr was just discovered and we have no connected peers,
                // it can mean that our network interfaces were not up but they are now
                // so it might be a good idea to trigger a bootstrap.
                self.bootstrap_status.trigger();
            }
            _ => {}
        }
    }
}

/// Peer Info combines a Peer ID with a set of multiaddrs that the peer is listening on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
}

/// A quorum w.r.t. the configured replication factor specifies the minimum
/// number of distinct nodes that must be successfully contacted in order
/// for a query to succeed.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Quorum {
    One,
    Majority,
    All,
    N(NonZeroUsize),
}

impl Quorum {
    /// Evaluate the quorum w.r.t a given total (number of peers).
    fn eval(&self, total: NonZeroUsize) -> NonZeroUsize {
        match self {
            Quorum::One => NonZeroUsize::new(1).expect("1 != 0"),
            Quorum::Majority => NonZeroUsize::new(total.get() / 2 + 1).expect("n + 1 != 0"),
            Quorum::All => total,
            Quorum::N(n) => NonZeroUsize::min(total, *n),
        }
    }
}

/// A record either received by the given peer or retrieved from the local
/// record store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// The peer from whom the record was received. `None` if the record was
    /// retrieved from local storage.
    pub peer: Option<PeerId>,
    pub record: Record,
}

//////////////////////////////////////////////////////////////////////////////
// Events

/// The events produced by the Kademlia behaviour.
///
/// These events are emitted by [`Behaviour`] via the [`NetworkBehaviour`] trait and delivered
/// to the application through [`SwarmEvent::Behaviour`](libp2p_swarm::SwarmEvent::Behaviour).
///
/// # Event Lifecycle
///
/// Events are generated in response to two broad categories of activity:
///
/// 1. **Inbound activity**: A remote peer sends a Kademlia protocol request to this node.
///    These produce [`Event::InboundRequest`] events, which are purely informational and do
///    not typically require a response from the application (the behaviour handles them
///    automatically), unless record filtering is enabled via [`Config::set_record_filtering`].
///
/// 2. **Outbound queries**: The application initiates a query (e.g. via [`Behaviour::get_record`],
///    [`Behaviour::put_record`], [`Behaviour::get_closest_peers`], [`Behaviour::get_providers`],
///    [`Behaviour::start_providing`], or [`Behaviour::bootstrap`]). These produce one or more
///    [`Event::OutboundQueryProgressed`] events as the query advances through the network. A query
///    fans out across multiple peers, and each intermediate or final result is reported through this
///    event. Use [`ProgressStep::last`] to determine when a query has completed.
///
/// 3. **Routing table changes**: As the DHT discovers, connects to, or loses peers, events such as
///    [`Event::RoutingUpdated`], [`Event::UnroutablePeer`], [`Event::RoutablePeer`], and
///    [`Event::PendingRoutablePeer`] inform the application about changes to the routing table.
///
/// # Difference Between Requests and Queries
///
/// A **request** is a single request-response exchange with one remote peer, while a **query** is
/// a multi-step operation that fans out across multiple peers using the Kademlia iterative lookup
/// algorithm. For example, [`Behaviour::get_record`] initiates a query that sends individual
/// `GetRecord` requests to multiple peers.
///
/// # From Provider Discovery to Connection
///
/// A common question is how to get from a [`record::Key`] to a working connection with a
/// provider of that key. Here is the typical workflow:
///
/// 1. Call [`Behaviour::get_providers`] with the key to discover providers.
/// 2. Receive [`GetProvidersOk::FoundProviders`] events, each containing a set of provider
///    [`PeerId`]s and their known addresses in `provider_addresses`.
/// 3. **Dial the provider directly** using `Swarm::dial(provider_peer_id)`. You do **not**
///    need to resolve the provider's address separately — Kademlia automatically learns
///    addresses of peers encountered during the query and feeds them to the swarm via
///    [`NetworkBehaviour::handle_pending_outbound_connection`]. The swarm will use these
///    cached addresses when dialing. You can also inspect the `providers` map to see
///    which addresses are known for each provider.
/// 4. Once a [`SwarmEvent::ConnectionEstablished`](libp2p_swarm::SwarmEvent::ConnectionEstablished)
///    event fires for the provider, you can communicate with it using your application protocol
///    (e.g. request-response, a custom stream protocol, etc.).
///
/// In short: Kademlia handles address resolution behind the scenes. The `providers` field
/// in [`GetProvidersOk::FoundProviders`] additionally exposes the known addresses for
/// each provider for inspection and debugging purposes.
///
/// # Using `PeerId` as a Lookup Key
///
/// If you know the exact [`PeerId`] of the peer you want to find (rather than looking up
/// an arbitrary content key), you can use [`Behaviour::get_closest_peers`] with the
/// [`PeerId`] directly, since `PeerId` satisfies the required trait bounds. This performs
/// an iterative lookup in the DHT keyspace, discovering both the target peer and its
/// neighbors. As with provider queries, addresses discovered during the lookup are
/// automatically cached and provided to the swarm for dialing.
///
/// Note that [`Behaviour::get_closest_peers`] finds peers *close to* the given key — it
/// does not guarantee that the target peer itself will be among the results unless it is
/// participating in the DHT. For content-addressed lookups, use [`Behaviour::get_providers`]
/// or [`Behaviour::get_record`] instead.
///
/// See [`NetworkBehaviour::poll`].
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// A remote peer has sent a Kademlia request to this node, and it has been handled.
    ///
    /// This is a **notification-only** event: the behaviour has already processed and responded
    /// to the request. The application does not need to take any action unless record filtering
    /// is enabled (see [`StoreInserts`] and [`Config::set_record_filtering`]), in which case
    /// the application must inspect [`InboundRequest::PutRecord`] or [`InboundRequest::AddProvider`]
    /// and decide whether to insert the record into the local store.
    ///
    /// This event is distinct from [`Event::OutboundQueryProgressed`], which reports progress
    /// on queries *initiated by the local node*. `InboundRequest` events are triggered by
    /// *remote* peers contacting this node.
    // Note on the difference between 'request' and 'query': A request is a
    // single request-response style exchange with a single remote peer. A query
    // is made of multiple requests across multiple remote peers.
    InboundRequest { request: InboundRequest },

    /// An outbound query initiated by the local node has made progress.
    ///
    /// This event is emitted one or more times for each query started via methods like
    /// [`Behaviour::get_record`], [`Behaviour::put_record`], [`Behaviour::get_closest_peers`],
    /// [`Behaviour::get_providers`], [`Behaviour::start_providing`], or [`Behaviour::bootstrap`].
    ///
    /// # Multiple Events per Query
    ///
    /// A single query can produce multiple `OutboundQueryProgressed` events. For example,
    /// [`Behaviour::get_record`] may emit a [`GetRecordOk::FoundRecord`] for each peer that
    /// returns the record, followed by a final [`GetRecordOk::FinishedWithNoAdditionalRecord`].
    /// Use [`ProgressStep::last`] to determine whether the query is complete.
    ///
    /// # Typical Handling
    ///
    /// Match on the [`QueryResult`] inside `result` to determine which type of query this
    /// event belongs to, then handle the `Ok` or `Err` variant accordingly. The `id` field
    /// lets you correlate this event with the [`QueryId`] returned by the method that started
    /// the query.
    OutboundQueryProgressed {
        /// The ID of the query that produced this event, as returned by methods like
        /// [`Behaviour::get_record`] or [`Behaviour::bootstrap`]. Use this to correlate
        /// events with the queries you initiated.
        id: QueryId,
        /// The intermediate or final result of the query. Match on the [`QueryResult`]
        /// variant to determine the query type (e.g. `GetRecord`, `PutRecord`, etc.) and
        /// inspect the inner `Ok` / `Err` value.
        result: QueryResult,
        /// Execution statistics from the query, including the number of requests made,
        /// successes, failures, and elapsed time.
        stats: QueryStats,
        /// Tracks the progress of multi-event queries. The `count` field indicates
        /// which event this is (1-indexed), and `last` is `true` when this is the
        /// final event for the query. Always check `step.last` to know when a query
        /// has fully completed.
        step: ProgressStep,
    },

    /// The routing table has been updated with a new peer and/or address, thereby possibly
    /// evicting another peer.
    ///
    /// This event is emitted when a peer is successfully inserted or updated in the Kademlia
    /// routing table (k-bucket). It may occur after a connection is established, after a
    /// successful Kademlia query response, or after an explicit call to
    /// [`Behaviour::add_address`].
    ///
    /// If `old_peer` is `Some`, a previously known peer was evicted from the routing table
    /// to make room for the new peer.
    ///
    /// # Difference from `RoutablePeer` and `PendingRoutablePeer`
    ///
    /// - [`Event::RoutingUpdated`]: The peer *was* added/updated in the routing table.
    /// - [`Event::RoutablePeer`]: The peer *could* be added but wasn't, because inserts are
    ///   manual or the bucket is full.
    /// - [`Event::PendingRoutablePeer`]: The peer is *pending* addition, waiting to see if
    ///   a disconnected peer is unresponsive.
    RoutingUpdated {
        /// The ID of the peer that was added or updated.
        peer: PeerId,
        /// `true` if this peer was not previously in the routing table and was just added.
        /// `false` if this peer was already present and only its addresses were updated.
        is_new_peer: bool,
        /// The full list of known addresses of `peer`.
        addresses: Addresses,
        /// The minimum inclusive and maximum inclusive [`Distance`] for
        /// the k-bucket that this peer belongs to.
        bucket_range: (Distance, Distance),
        /// The ID of the peer that was evicted from the routing table to make
        /// room for the new peer, if any. When `None`, no peer was evicted.
        old_peer: Option<PeerId>,
    },

    /// A peer has connected for whom no listen address is known.
    ///
    /// This event occurs during connection establishment when the Kademlia behaviour observes
    /// a new peer but has no known listen address for it. Without a listen address, the peer
    /// cannot be added to the routing table because Kademlia needs routable addresses to
    /// function correctly.
    ///
    /// # Recommended Action
    ///
    /// If the peer is to be added to the routing table, a known listen address must be
    /// provided via [`Behaviour::add_address`]. If you do not need this peer in the routing
    /// table, this event can be safely ignored.
    ///
    /// # Difference from `RoutablePeer`
    ///
    /// - `UnroutablePeer`: No listen address is known at all.
    /// - [`Event::RoutablePeer`]: A listen address is known, but the peer was not inserted
    ///   into the routing table for other reasons (e.g. manual inserts or full bucket).
    UnroutablePeer { peer: PeerId },

    /// A connection to a peer has been established for whom a listen address
    /// is known but the peer has not been added to the routing table either
    /// because [`BucketInserts::Manual`] is configured or because
    /// the corresponding bucket is full.
    ///
    /// This event occurs during connection establishment when the Kademlia behaviour
    /// has an address for the peer but cannot or will not automatically insert it into
    /// the routing table.
    ///
    /// # Recommended Action
    ///
    /// If the peer is to be included in the routing table, it must
    /// be explicitly added via [`Behaviour::add_address`], possibly after
    /// removing another peer to make room.
    ///
    /// # Difference from `UnroutablePeer` and `PendingRoutablePeer`
    ///
    /// - [`Event::UnroutablePeer`]: No listen address is known at all.
    /// - `RoutablePeer`: A listen address is known but the peer was not inserted due to
    ///   manual insert mode or a full bucket.
    /// - [`Event::PendingRoutablePeer`]: A listen address is known and the peer is pending
    ///   insertion (waiting for a disconnected peer to be evicted).
    ///
    /// See [`Behaviour::kbucket`] for insight into the contents of
    /// the k-bucket of `peer`.
    RoutablePeer { peer: PeerId, address: Multiaddr },

    /// A connection to a peer has been established for whom a listen address
    /// is known but the peer is only pending insertion into the routing table
    /// if the least-recently disconnected peer is unresponsive, i.e. the peer
    /// may not make it into the routing table.
    ///
    /// This event occurs when the k-bucket for this peer is full and the new peer
    /// has been placed in a pending slot. The Kademlia protocol will attempt to contact
    /// the least-recently disconnected peer in the bucket, and if that peer does not
    /// respond, the pending peer will be inserted (producing a [`Event::RoutingUpdated`]
    /// event).
    ///
    /// # Recommended Action
    ///
    /// If the peer is to be unconditionally included in the routing table,
    /// it should be explicitly added via [`Behaviour::add_address`] after
    /// removing another peer.
    ///
    /// # Difference from `RoutablePeer`
    ///
    /// - [`Event::RoutablePeer`]: The peer was *not* inserted and is *not* pending.
    /// - `PendingRoutablePeer`: The peer is *pending* insertion and may eventually be
    ///   inserted automatically.
    ///
    /// See [`Behaviour::kbucket`] for insight into the contents of
    /// the k-bucket of `peer`.
    PendingRoutablePeer { peer: PeerId, address: Multiaddr },

    /// This peer's Kademlia mode has been updated automatically.
    ///
    /// The Kademlia mode determines whether this node acts as a **server** (responds to
    /// incoming Kademlia requests from other peers) or a **client** (only initiates queries
    /// but does not serve requests).
    ///
    /// This event is emitted when the mode changes automatically in response to an external
    /// address being added or removed. When the node has a confirmed external address, it
    /// typically switches to server mode; when the external address is lost, it may revert
    /// to client mode.
    ///
    /// # Recommended Action
    ///
    /// This is informational. You may want to log mode changes or adjust application
    /// behaviour based on whether the node is acting as a full DHT server or client-only.
    ModeChanged { new_mode: Mode },
}

/// Tracks the progress of a multi-step [`Event::OutboundQueryProgressed`] sequence.
///
/// Some Kademlia queries produce multiple progress events before completing. For example,
/// a [`Behaviour::get_record`] query may emit one [`GetRecordOk::FoundRecord`] for each
/// peer that returns the record, followed by a final [`GetRecordOk::FinishedWithNoAdditionalRecord`].
///
/// # Fields
///
/// - `count`: A 1-indexed counter indicating which event in the sequence this is.
/// - `last`: `true` when this is the final event for the query. After receiving an event
///   where `last == true`, no more events will be emitted for this [`QueryId`].
///
/// # Typical Usage
///
/// ```ignore
/// if step.last {
///     // The query is complete — finalize processing.
/// } else {
///     // More results may follow — accumulate intermediate results.
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ProgressStep {
    /// The 1-indexed position of this event in the sequence of progress events
    /// for a given query.
    pub count: NonZeroUsize,
    /// `true` if this is the final event for the query. No more
    /// [`Event::OutboundQueryProgressed`] events with this [`QueryId`] will follow.
    pub last: bool,
}

impl ProgressStep {
    fn first() -> Self {
        Self {
            count: NonZeroUsize::new(1).expect("1 to be greater than 0."),
            last: false,
        }
    }

    fn first_and_last() -> Self {
        let mut first = ProgressStep::first();
        first.last = true;
        first
    }

    fn next(&self) -> Self {
        assert!(!self.last);
        let count = NonZeroUsize::new(self.count.get() + 1).expect("Adding 1 not to result in 0.");

        Self { count, last: false }
    }
}

/// Information about a Kademlia request received from a remote peer and handled by this node.
///
/// These variants describe the type of inbound request that was processed. The behaviour
/// has already sent a response to the remote peer. This event is informational unless
/// record filtering is enabled (see [`StoreInserts`] and [`Config::set_record_filtering`]),
/// in which case the application must inspect [`InboundRequest::PutRecord`] or
/// [`InboundRequest::AddProvider`] to decide whether to store the record.
///
/// # Variants Overview
///
/// | Variant | Remote is asking | When it occurs |
/// |---------|-----------------|----------------|
/// | [`FindNode`](InboundRequest::FindNode) | "Who are the closest peers to this key?" | During peer discovery / routing table maintenance |
/// | [`GetProvider`](InboundRequest::GetProvider) | "Who provides content for this key?" | When a peer looks up content providers |
/// | [`AddProvider`](InboundRequest::AddProvider) | "I am a provider for this key" | When a peer announces itself as a provider |
/// | [`GetRecord`](InboundRequest::GetRecord) | "Do you have the value for this key?" | During DHT record lookups |
/// | [`PutRecord`](InboundRequest::PutRecord) | "Please store this record" | During DHT record storage / replication |
#[derive(Debug, Clone)]
pub enum InboundRequest {
    /// A remote peer requested the list of nodes whose IDs are closest to a given key.
    ///
    /// This is the most fundamental Kademlia operation, used during iterative lookups and
    /// routing table maintenance. The response (already sent) contains up to `k` closest
    /// peers known to this node.
    FindNode { num_closer_peers: usize },
    /// A remote peer requested content providers for a given key, along with closer peers.
    ///
    /// Similar to [`FindNode`](InboundRequest::FindNode), but the response also includes
    /// any peers known to this node that have announced themselves as providers for the key.
    GetProvider {
        num_closer_peers: usize,
        num_provider_peers: usize,
    },
    /// A remote peer announced itself as a provider for a given key.
    ///
    /// When record filtering is enabled via [`StoreInserts::FilterBoth`], the
    /// [`ProviderRecord`] is included so the application can decide whether to accept
    /// and store the provider announcement. When filtering is not enabled, the provider
    /// record is stored automatically and `record` is `None`.
    ///
    /// See [`StoreInserts`] and [`Config::set_record_filtering`] for details.
    AddProvider { record: Option<ProviderRecord> },
    /// A remote peer requested a record by key.
    ///
    /// The `present_locally` field indicates whether this node had the record in its
    /// local store at the time of the request. `num_closer_peers` indicates how many
    /// closer peers were included in the response regardless.
    GetRecord {
        num_closer_peers: usize,
        present_locally: bool,
    },
    /// A remote peer asked this node to store a record.
    ///
    /// When record filtering is enabled via [`StoreInserts::FilterBoth`], the [`Record`]
    /// is included so the application can validate and decide whether to store it. When
    /// filtering is not enabled, the record is stored automatically and `record` is `None`.
    ///
    /// See [`StoreInserts`] and [`Config::set_record_filtering`].
    PutRecord {
        source: PeerId,
        connection: ConnectionId,
        record: Option<Record>,
    },
}

/// The result of an outbound Kademlia query, delivered inside
/// [`Event::OutboundQueryProgressed`].
///
/// Each variant wraps a `Result<..Ok, ..Error>` type corresponding to one of the query
/// methods on [`Behaviour`]. Match on this enum to determine which kind of query produced
/// the event, then inspect the inner `Ok` or `Err` to handle the result.
///
/// # Variants and Their Originating Methods
///
/// | Variant | Initiated by | Description |
/// |---------|-------------|-------------|
/// | [`Bootstrap`](QueryResult::Bootstrap) | [`Behaviour::bootstrap`] | Populates the routing table by querying peers closest to the local node's ID |
/// | [`GetClosestPeers`](QueryResult::GetClosestPeers) | [`Behaviour::get_closest_peers`] | Finds the `k` closest peers to a given key |
/// | [`GetProviders`](QueryResult::GetProviders) | [`Behaviour::get_providers`] | Discovers which peers provide content for a given key |
/// | [`StartProviding`](QueryResult::StartProviding) | [`Behaviour::start_providing`] | Announces this node as a provider for a given key |
/// | [`RepublishProvider`](QueryResult::RepublishProvider) | *(automatic)* | Periodically re-announces provider records to maintain them in the DHT |
/// | [`GetRecord`](QueryResult::GetRecord) | [`Behaviour::get_record`] | Retrieves a value record from the DHT |
/// | [`PutRecord`](QueryResult::PutRecord) | [`Behaviour::put_record`] | Stores a value record in the DHT |
/// | [`RepublishRecord`](QueryResult::RepublishRecord) | *(automatic)* | Periodically re-publishes value records to maintain them in the DHT |
#[derive(Debug, Clone)]
pub enum QueryResult {
    /// The result of [`Behaviour::bootstrap`].
    ///
    /// Bootstrap populates the routing table by performing iterative lookups for the
    /// local node's own ID and then for random keys in each k-bucket. Multiple
    /// progress events may be emitted (one per bucket), with [`BootstrapOk::num_remaining`]
    /// indicating how many buckets are left. The query is complete when `num_remaining == 0`
    /// (and [`ProgressStep::last`] is `true`).
    Bootstrap(BootstrapResult),

    /// The result of [`Behaviour::get_closest_peers`].
    ///
    /// Returns the peers closest to a given key as determined by the Kademlia XOR distance
    /// metric. This is a single-result query: one event is emitted when the iterative
    /// lookup completes (or times out).
    GetClosestPeers(GetClosestPeersResult),

    /// The result of [`Behaviour::get_providers`].
    ///
    /// May emit multiple progress events: one [`GetProvidersOk::FoundProviders`] for each
    /// batch of providers discovered, followed by a final
    /// [`GetProvidersOk::FinishedWithNoAdditionalRecord`] when the query completes.
    GetProviders(GetProvidersResult),

    /// The result of [`Behaviour::start_providing`].
    ///
    /// Indicates whether the provider announcement was successfully published to the
    /// closest peers. This is the result of the *initial* announcement; subsequent
    /// automatic re-publications produce [`QueryResult::RepublishProvider`] events.
    StartProviding(AddProviderResult),

    /// The result of an automatic republication of a provider record.
    ///
    /// Provider records have a limited time-to-live in the DHT. The behaviour
    /// automatically re-publishes them at regular intervals (configured via
    /// [`Config::set_provider_publication_interval`]). This event reports the outcome
    /// of such a re-publication. Compare with [`QueryResult::StartProviding`], which
    /// reports the result of the *initial* publication.
    RepublishProvider(AddProviderResult),

    /// The result of [`Behaviour::get_record`].
    ///
    /// May emit multiple progress events: one [`GetRecordOk::FoundRecord`] for each peer
    /// that returns the record, followed by a final
    /// [`GetRecordOk::FinishedWithNoAdditionalRecord`] when the query completes. Use
    /// [`ProgressStep::last`] to detect the final event.
    GetRecord(GetRecordResult),

    /// The result of [`Behaviour::put_record`].
    ///
    /// Emitted when the record has been stored on sufficient peers (quorum reached)
    /// or when the query fails/times out. This is the result of the *initial* put;
    /// subsequent automatic re-publications produce [`QueryResult::RepublishRecord`].
    PutRecord(PutRecordResult),

    /// The result of an automatic republication of a value record.
    ///
    /// Value records have a limited time-to-live in the DHT. The behaviour
    /// automatically re-publishes them at regular intervals (configured via
    /// [`Config::set_publication_interval`]). This event reports the outcome
    /// of such a re-publication. Compare with [`QueryResult::PutRecord`], which
    /// reports the result of the *initial* put operation.
    RepublishRecord(PutRecordResult),
}

/// The result of [`Behaviour::get_record`].
///
/// An `Ok` value indicates the query found records or completed successfully; an `Err`
/// value indicates a failure (not found, quorum not reached, or timeout).
pub type GetRecordResult = Result<GetRecordOk, GetRecordError>;

/// The successful result of [`Behaviour::get_record`].
///
/// This enum has two variants because a `get_record` query may emit multiple progress
/// events. Each time a peer returns the requested record, a [`GetRecordOk::FoundRecord`]
/// event is emitted. When the query finishes with no additional records to report,
/// [`GetRecordOk::FinishedWithNoAdditionalRecord`] is emitted as the final event.
///
/// # Typical Usage
///
/// ```ignore
/// match event {
///     GetRecordOk::FoundRecord(peer_record) => {
///         // A peer returned the record — collect it.
///     }
///     GetRecordOk::FinishedWithNoAdditionalRecord { cache_candidates } => {
///         // The query is complete. Optionally write back the record to
///         // cache_candidates using Behaviour::put_record_to.
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum GetRecordOk {
    /// A peer returned the requested record.
    ///
    /// This variant may be emitted multiple times during a single query — once for each
    /// peer that holds the record. The enclosed [`PeerRecord`] contains the record value
    /// and the peer that returned it. Check [`ProgressStep::last`] in the enclosing
    /// [`Event::OutboundQueryProgressed`] to know if more results may follow.
    FoundRecord(PeerRecord),
    /// The query has finished and no additional records were found.
    ///
    /// This is always the **final** event for a `get_record` query (i.e.
    /// [`ProgressStep::last`] will be `true`). If caching is enabled, the
    /// `cache_candidates` field contains peers that were close to the record key
    /// but did not hold the record, which are good candidates for caching.
    FinishedWithNoAdditionalRecord {
        /// If caching is enabled, these are the peers closest
        /// _to the record key_ (not the local node) that were queried but
        /// did not return the record, sorted by distance to the record key
        /// from closest to farthest. How many of these are tracked is configured
        /// by [`Config::set_caching`].
        ///
        /// Writing back the cache at these peers is a manual operation.
        /// ie. you may wish to use these candidates with [`Behaviour::put_record_to`]
        /// after selecting one of the returned records.
        cache_candidates: BTreeMap<kbucket::Distance, PeerId>,
    },
}

/// The error result of [`Behaviour::get_record`].
///
/// Returned inside [`QueryResult::GetRecord`] when the record lookup fails.
///
/// # Variants
///
/// - [`NotFound`](GetRecordError::NotFound): The iterative lookup completed but no peer held
///   the record. The `closest_peers` are the peers that were closest to the key.
/// - [`QuorumFailed`](GetRecordError::QuorumFailed): Some peers returned the record, but not
///   enough to meet the configured quorum. The partial results are available in `records`.
/// - [`Timeout`](GetRecordError::Timeout): The query did not complete within the configured
///   timeout.
#[derive(Debug, Clone, Error)]
pub enum GetRecordError {
    /// The record was not found on any of the queried peers.
    ///
    /// The `closest_peers` field contains the peers that were closest to the key,
    /// which may be useful for diagnostics or manual caching.
    #[error("the record was not found")]
    NotFound {
        key: record::Key,
        closest_peers: Vec<PeerId>,
    },
    /// The record was found on some peers, but the quorum requirement was not met.
    ///
    /// The `records` field contains the partial results that were retrieved. The
    /// application may choose to use one of these records despite the quorum failure,
    /// or retry the query.
    #[error("the quorum failed; needed {quorum} peers")]
    QuorumFailed {
        key: record::Key,
        records: Vec<PeerRecord>,
        quorum: NonZeroUsize,
    },
    /// The query timed out before completing.
    ///
    /// It is unknown how many peers were queried or whether the record exists.
    #[error("the request timed out")]
    Timeout { key: record::Key },
}

impl GetRecordError {
    /// Gets the key of the record for which the operation failed.
    pub fn key(&self) -> &record::Key {
        match self {
            GetRecordError::QuorumFailed { key, .. } => key,
            GetRecordError::Timeout { key, .. } => key,
            GetRecordError::NotFound { key, .. } => key,
        }
    }

    /// Extracts the key of the record for which the operation failed,
    /// consuming the error.
    pub fn into_key(self) -> record::Key {
        match self {
            GetRecordError::QuorumFailed { key, .. } => key,
            GetRecordError::Timeout { key, .. } => key,
            GetRecordError::NotFound { key, .. } => key,
        }
    }
}

/// The result of [`Behaviour::put_record`].
///
/// An `Ok` value indicates the record was stored on enough peers to satisfy the quorum;
/// an `Err` value indicates the quorum was not reached or the query timed out.
pub type PutRecordResult = Result<PutRecordOk, PutRecordError>;

/// The successful result of [`Behaviour::put_record`].
///
/// Emitted when the record has been successfully stored on at least as many peers as
/// required by the quorum. The `key` identifies which record was stored.
#[derive(Debug, Clone)]
pub struct PutRecordOk {
    pub key: record::Key,
}

/// The error result of [`Behaviour::put_record`].
///
/// Returned inside [`QueryResult::PutRecord`] or [`QueryResult::RepublishRecord`] when the
/// record could not be stored on enough peers.
///
/// # Variants
///
/// - [`QuorumFailed`](PutRecordError::QuorumFailed): Some peers stored the record, but not
///   enough to meet the quorum. The `success` field lists peers that *did* store it.
/// - [`Timeout`](PutRecordError::Timeout): The query timed out. The `success` field lists
///   any peers that stored the record before the timeout.
#[derive(Debug, Clone, Error)]
pub enum PutRecordError {
    /// Some peers stored the record, but the quorum requirement was not met.
    ///
    /// The `success` field contains the peers that successfully stored the record.
    /// The application may decide to retry or accept the partial result.
    #[error("the quorum failed; needed {quorum} peers")]
    QuorumFailed {
        key: record::Key,
        /// [`PeerId`]s of the peers the record was successfully stored on.
        success: Vec<PeerId>,
        quorum: NonZeroUsize,
    },
    /// The query timed out before the quorum could be reached.
    ///
    /// The `success` field contains the peers that stored the record before
    /// the timeout occurred.
    #[error("the request timed out")]
    Timeout {
        key: record::Key,
        /// [`PeerId`]s of the peers the record was successfully stored on.
        success: Vec<PeerId>,
        quorum: NonZeroUsize,
    },
}

impl PutRecordError {
    /// Gets the key of the record for which the operation failed.
    pub fn key(&self) -> &record::Key {
        match self {
            PutRecordError::QuorumFailed { key, .. } => key,
            PutRecordError::Timeout { key, .. } => key,
        }
    }

    /// Extracts the key of the record for which the operation failed,
    /// consuming the error.
    pub fn into_key(self) -> record::Key {
        match self {
            PutRecordError::QuorumFailed { key, .. } => key,
            PutRecordError::Timeout { key, .. } => key,
        }
    }
}

/// The result of [`Behaviour::bootstrap`].
///
/// An `Ok` value indicates progress or successful completion of the bootstrap process;
/// an `Err` value indicates a timeout.
pub type BootstrapResult = Result<BootstrapOk, BootstrapError>;

/// The successful result of [`Behaviour::bootstrap`].
///
/// Bootstrap is a multi-step process that populates the routing table by looking up peers
/// in each k-bucket. This event is emitted once per k-bucket that is refreshed. The
/// `num_remaining` field counts how many buckets still need to be refreshed. When
/// `num_remaining == 0`, the bootstrap process is complete.
///
/// # Fields
///
/// - `peer`: The peer ID that was used as the target of the lookup for this step (typically
///   a random key in the bucket's range, or the local peer ID for the first step).
/// - `num_remaining`: The number of k-buckets remaining to be refreshed. When this reaches
///   `0`, the bootstrap is fully complete.
#[derive(Debug, Clone)]
pub struct BootstrapOk {
    pub peer: PeerId,
    pub num_remaining: u32,
}

/// The error result of [`Behaviour::bootstrap`].
///
/// Currently the only failure mode is a timeout, which means the iterative lookup for
/// a particular k-bucket did not complete in time.
#[derive(Debug, Clone, Error)]
pub enum BootstrapError {
    /// The bootstrap query for a particular bucket timed out.
    ///
    /// `num_remaining` indicates how many buckets were still left to refresh, if known.
    /// A `None` value means the number of remaining buckets could not be determined.
    #[error("the request timed out")]
    Timeout {
        peer: PeerId,
        num_remaining: Option<u32>,
    },
}

/// The result of [`Behaviour::get_closest_peers`].
///
/// An `Ok` value contains the closest peers found; an `Err` value indicates
/// a timeout (which still includes the best peers found so far).
pub type GetClosestPeersResult = Result<GetClosestPeersOk, GetClosestPeersError>;

/// The successful result of [`Behaviour::get_closest_peers`].
///
/// Contains the peers that are closest to the given key according to the Kademlia XOR
/// distance metric. The `peers` list is sorted by distance from closest to farthest
/// and contains at most `k` entries (where `k` is the replication factor, typically 20).
///
/// This is a single-event query: exactly one `OutboundQueryProgressed` event is emitted
/// with [`ProgressStep::last`] set to `true`.
#[derive(Debug, Clone)]
pub struct GetClosestPeersOk {
    pub key: Vec<u8>,
    pub peers: Vec<PeerInfo>,
}

/// The error result of [`Behaviour::get_closest_peers`].
///
/// Currently the only failure mode is a timeout.
#[derive(Debug, Clone, Error)]
pub enum GetClosestPeersError {
    /// The query timed out before completing.
    ///
    /// The `peers` field still contains the closest peers found before the timeout,
    /// which may be useful despite the incomplete result.
    #[error("the request timed out")]
    Timeout { key: Vec<u8>, peers: Vec<PeerInfo> },
}

impl GetClosestPeersError {
    /// Gets the key for which the operation failed.
    pub fn key(&self) -> &Vec<u8> {
        match self {
            GetClosestPeersError::Timeout { key, .. } => key,
        }
    }

    /// Extracts the key for which the operation failed,
    /// consuming the error.
    pub fn into_key(self) -> Vec<u8> {
        match self {
            GetClosestPeersError::Timeout { key, .. } => key,
        }
    }
}

/// The result of [`Behaviour::get_providers`].
///
/// An `Ok` value indicates providers were found or the query completed; an `Err` value
/// indicates a timeout.
pub type GetProvidersResult = Result<GetProvidersOk, GetProvidersError>;

/// The successful result of [`Behaviour::get_providers`].
///
/// This query may emit multiple progress events. Each [`GetProvidersOk::FoundProviders`]
/// event contains a batch of newly discovered providers. When the query finishes,
/// a final [`GetProvidersOk::FinishedWithNoAdditionalRecord`] event is emitted. Use
/// [`ProgressStep::last`] to detect the final event.
///
/// # Connecting to Discovered Providers
///
/// The `providers` field is a map from each provider's [`PeerId`] to their known
/// [`Multiaddr`]s. Use `providers.keys()` to iterate over just the [`PeerId`]s.
/// During the iterative lookup, the Kademlia behaviour automatically learns
/// and caches the addresses of all peers it contacts (including providers). When you
/// subsequently dial a provider via `Swarm::dial(provider_peer_id)`, the swarm will obtain
/// the provider's address from the Kademlia behaviour's cache via
/// [`NetworkBehaviour::handle_pending_outbound_connection`].
///
/// In short, you can dial providers by [`PeerId`] alone — no separate address resolution
/// step is needed. The addresses in `providers` are provided for transparency and debugging.
///
/// # Typical Usage
///
/// ```ignore
/// // Accumulate providers across multiple events:
/// let mut all_providers = HashMap::new();
/// // ... in your event loop:
/// match result {
///     GetProvidersOk::FoundProviders { providers, .. } => {
///         all_providers.extend(providers);
///         // Optionally dial providers as they are discovered:
///         for provider in all_providers.keys() {
///             swarm.dial(*provider).ok();
///         }
///     }
///     GetProvidersOk::FinishedWithNoAdditionalRecord { .. } => {
///         // Query complete — all_providers contains every discovered provider.
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum GetProvidersOk {
    /// A new batch of providers was discovered during the query.
    ///
    /// This variant may be emitted multiple times as the iterative lookup progresses
    /// and different peers respond with their knowledge of providers.
    ///
    /// The providers can be dialed directly by [`PeerId`] — Kademlia automatically
    /// caches their addresses during the lookup and provides them to the swarm for
    /// dialing. No separate address resolution is needed.
    FoundProviders {
        key: record::Key,
        /// The providers discovered in this batch, mapped to their known addresses.
        ///
        /// These are *additional* providers not previously reported in earlier
        /// `FoundProviders` events for the same query. Use `providers.keys()` to
        /// iterate over just the [`PeerId`]s. Addresses are also cached internally
        /// and provided to the swarm automatically when dialing.
        ///
        /// The addresses are those known at the time the event is emitted. For
        /// locally stored provider records, these are the addresses stored with the
        /// record. For remotely discovered providers, these are the addresses
        /// reported by the responding peer.
        ///
        /// Note that these addresses may not be exhaustive — additional addresses
        /// may be discovered later or may already be cached in the routing table.
        providers: HashMap<PeerId, Vec<Multiaddr>>,
    },
    /// The query has finished and no additional providers were found.
    ///
    /// This is always the **final** event for a `get_providers` query (i.e.
    /// [`ProgressStep::last`] will be `true`). The `closest_peers` field contains
    /// the peers closest to the key, which may be useful for diagnostics.
    FinishedWithNoAdditionalRecord {
        closest_peers: Vec<PeerId>,
    },
}

/// The error result of [`Behaviour::get_providers`].
///
/// Currently the only failure mode is a timeout.
#[derive(Debug, Clone, Error)]
pub enum GetProvidersError {
    /// The query timed out before completing.
    ///
    /// The `closest_peers` field contains the closest peers found before the timeout,
    /// which may still be useful.
    #[error("the request timed out")]
    Timeout {
        key: record::Key,
        closest_peers: Vec<PeerId>,
    },
}

impl GetProvidersError {
    /// Gets the key for which the operation failed.
    pub fn key(&self) -> &record::Key {
        match self {
            GetProvidersError::Timeout { key, .. } => key,
        }
    }

    /// Extracts the key for which the operation failed,
    /// consuming the error.
    pub fn into_key(self) -> record::Key {
        match self {
            GetProvidersError::Timeout { key, .. } => key,
        }
    }
}

/// The result of publishing a provider record via [`Behaviour::start_providing`] or
/// an automatic republication.
///
/// An `Ok` value indicates the provider record was successfully announced to the closest
/// peers; an `Err` value indicates a timeout.
pub type AddProviderResult = Result<AddProviderOk, AddProviderError>;

/// The successful result of publishing a provider record.
///
/// Indicates that this node has been successfully announced as a provider for the given
/// key to the peers closest to that key in the DHT.
#[derive(Debug, Clone)]
pub struct AddProviderOk {
    pub key: record::Key,
}

/// The possible errors when publishing a provider record.
///
/// Returned inside [`QueryResult::StartProviding`] or [`QueryResult::RepublishProvider`]
/// when the provider announcement fails.
#[derive(Debug, Clone, Error)]
pub enum AddProviderError {
    /// The query timed out before the provider record could be published to
    /// enough peers.
    #[error("the request timed out")]
    Timeout { key: record::Key },
}

impl AddProviderError {
    /// Gets the key for which the operation failed.
    pub fn key(&self) -> &record::Key {
        match self {
            AddProviderError::Timeout { key, .. } => key,
        }
    }

    /// Extracts the key for which the operation failed,
    pub fn into_key(self) -> record::Key {
        match self {
            AddProviderError::Timeout { key, .. } => key,
        }
    }
}

impl From<kbucket::EntryView<kbucket::Key<PeerId>, Addresses>> for KadPeer {
    fn from(e: kbucket::EntryView<kbucket::Key<PeerId>, Addresses>) -> KadPeer {
        KadPeer {
            node_id: e.node.key.into_preimage(),
            multiaddrs: e.node.value.into_vec(),
            connection_ty: match e.status {
                NodeStatus::Connected => ConnectionType::Connected,
                NodeStatus::Disconnected => ConnectionType::NotConnected,
            },
        }
    }
}

/// The context of a [`QueryInfo::AddProvider`] query.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddProviderContext {
    /// The context is a [`Behaviour::start_providing`] operation.
    Publish,
    /// The context is periodic republishing of provider announcements
    /// initiated earlier via [`Behaviour::start_providing`].
    Republish,
}

/// The context of a [`QueryInfo::PutRecord`] query.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PutRecordContext {
    /// The context is a [`Behaviour::put_record`] operation.
    Publish,
    /// The context is periodic republishing of records stored
    /// earlier via [`Behaviour::put_record`].
    Republish,
    /// The context is periodic replication (i.e. without extending
    /// the record TTL) of stored records received earlier from another peer.
    Replicate,
    /// The context is a custom store operation targeting specific
    /// peers initiated by [`Behaviour::put_record_to`].
    Custom,
}

/// Information about a running query.
#[derive(Debug, Clone)]
pub enum QueryInfo {
    /// A query initiated by [`Behaviour::bootstrap`].
    Bootstrap {
        /// The targeted peer ID.
        peer: PeerId,
        /// The remaining random peer IDs to query, one per
        /// bucket that still needs refreshing.
        ///
        /// This is `None` if the initial self-lookup has not
        /// yet completed and `Some` with an exhausted iterator
        /// if bootstrapping is complete.
        remaining: Option<vec::IntoIter<kbucket::Key<PeerId>>>,
        step: ProgressStep,
    },

    /// A (repeated) query initiated by [`Behaviour::get_closest_peers`].
    GetClosestPeers {
        /// The key being queried (the preimage).
        key: Vec<u8>,
        /// Current index of events.
        step: ProgressStep,
        /// If required, `num_results` specifies expected responding peers
        num_results: Option<NonZeroUsize>,
    },

    /// A (repeated) query initiated by [`Behaviour::get_providers`].
    GetProviders {
        /// The key for which to search for providers.
        key: record::Key,
        /// The number of providers found so far.
        providers_found: usize,
        /// Current index of events.
        step: ProgressStep,
    },

    /// A (repeated) query initiated by [`Behaviour::start_providing`].
    AddProvider {
        /// The record key.
        key: record::Key,
        /// The current phase of the query.
        phase: AddProviderPhase,
        /// The execution context of the query.
        context: AddProviderContext,
    },

    /// A (repeated) query initiated by [`Behaviour::put_record`].
    PutRecord {
        record: Record,
        /// The expected quorum of responses w.r.t. the replication factor.
        quorum: NonZeroUsize,
        /// The current phase of the query.
        phase: PutRecordPhase,
        /// The execution context of the query.
        context: PutRecordContext,
    },

    /// A (repeated) query initiated by [`Behaviour::get_record`].
    GetRecord {
        /// The key to look for.
        key: record::Key,
        /// Current index of events.
        step: ProgressStep,
        /// Did we find at least one record?
        found_a_record: bool,
        /// The peers closest to the `key` that were queried but did not return a record,
        /// i.e. the peers that are candidates for caching the record.
        cache_candidates: BTreeMap<kbucket::Distance, PeerId>,
    },
}

impl QueryInfo {
    /// Creates an event for a handler to issue an outgoing request in the
    /// context of a query.
    fn to_request(&self, query_id: QueryId) -> HandlerIn {
        match &self {
            QueryInfo::Bootstrap { peer, .. } => HandlerIn::FindNodeReq {
                key: peer.to_bytes(),
                query_id,
            },
            QueryInfo::GetClosestPeers { key, .. } => HandlerIn::FindNodeReq {
                key: key.clone(),
                query_id,
            },
            QueryInfo::GetProviders { key, .. } => HandlerIn::GetProvidersReq {
                key: key.clone(),
                query_id,
            },
            QueryInfo::AddProvider { key, phase, .. } => match phase {
                AddProviderPhase::GetClosestPeers => HandlerIn::FindNodeReq {
                    key: key.to_vec(),
                    query_id,
                },
                AddProviderPhase::AddProvider {
                    provider_id,
                    external_addresses,
                    ..
                } => HandlerIn::AddProvider {
                    key: key.clone(),
                    provider: crate::protocol::KadPeer {
                        node_id: *provider_id,
                        multiaddrs: external_addresses.clone(),
                        connection_ty: crate::protocol::ConnectionType::Connected,
                    },
                    query_id,
                },
            },
            QueryInfo::GetRecord { key, .. } => HandlerIn::GetRecord {
                key: key.clone(),
                query_id,
            },
            QueryInfo::PutRecord { record, phase, .. } => match phase {
                PutRecordPhase::GetClosestPeers => HandlerIn::FindNodeReq {
                    key: record.key.to_vec(),
                    query_id,
                },
                PutRecordPhase::PutRecord { .. } => HandlerIn::PutRecord {
                    record: record.clone(),
                    query_id,
                },
            },
        }
    }
}

/// The phases of a [`QueryInfo::AddProvider`] query.
#[derive(Debug, Clone)]
pub enum AddProviderPhase {
    /// The query is searching for the closest nodes to the record key.
    GetClosestPeers,

    /// The query advertises the local node as a provider for the key to
    /// the closest nodes to the key.
    AddProvider {
        /// The local peer ID that is advertised as a provider.
        provider_id: PeerId,
        /// The external addresses of the provider being advertised.
        external_addresses: Vec<Multiaddr>,
        /// Query statistics from the finished `GetClosestPeers` phase.
        get_closest_peers_stats: QueryStats,
    },
}

/// The phases of a [`QueryInfo::PutRecord`] query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutRecordPhase {
    /// The query is searching for the closest nodes to the record key.
    GetClosestPeers,

    /// The query is replicating the record to the closest nodes to the key.
    PutRecord {
        /// A list of peers the given record has been successfully replicated to.
        success: Vec<PeerId>,
        /// Query statistics from the finished `GetClosestPeers` phase.
        get_closest_peers_stats: QueryStats,
    },
}

/// A mutable reference to a running query.
pub struct QueryMut<'a> {
    query: &'a mut Query,
}

impl QueryMut<'_> {
    pub fn id(&self) -> QueryId {
        self.query.id()
    }

    /// Gets information about the type and state of the query.
    pub fn info(&self) -> &QueryInfo {
        &self.query.info
    }

    /// Gets execution statistics about the query.
    ///
    /// For a multi-phase query such as `put_record`, these are the
    /// statistics of the current phase.
    pub fn stats(&self) -> &QueryStats {
        self.query.stats()
    }

    /// Finishes the query asap, without waiting for the
    /// regular termination conditions.
    pub fn finish(&mut self) {
        self.query.finish()
    }
}

/// An immutable reference to a running query.
pub struct QueryRef<'a> {
    query: &'a Query,
}

impl QueryRef<'_> {
    pub fn id(&self) -> QueryId {
        self.query.id()
    }

    /// Gets information about the type and state of the query.
    pub fn info(&self) -> &QueryInfo {
        &self.query.info
    }

    /// Gets execution statistics about the query.
    ///
    /// For a multi-phase query such as `put_record`, these are the
    /// statistics of the current phase.
    pub fn stats(&self) -> &QueryStats {
        self.query.stats()
    }
}

/// An operation failed to due no known peers in the routing table.
#[derive(Debug, Clone)]
pub struct NoKnownPeers();

impl fmt::Display for NoKnownPeers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No known peers.")
    }
}

impl std::error::Error for NoKnownPeers {}

/// The possible outcomes of [`Behaviour::add_address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingUpdate {
    /// The given peer and address has been added to the routing
    /// table.
    Success,
    /// The peer and address is pending insertion into
    /// the routing table, if a disconnected peer fails
    /// to respond. If the given peer and address ends up
    /// in the routing table, [`Event::RoutingUpdated`]
    /// is eventually emitted.
    Pending,
    /// The routing table update failed, either because the
    /// corresponding bucket for the peer is full and the
    /// pending slot(s) are occupied, or because the given
    /// peer ID is deemed invalid (e.g. refers to the local
    /// peer ID).
    Failed,
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum Mode {
    Client,
    Server,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Client => write!(f, "client"),
            Mode::Server => write!(f, "server"),
        }
    }
}

fn to_comma_separated_list<T>(confirmed_external_addresses: &[T]) -> String
where
    T: ToString,
{
    confirmed_external_addresses
        .iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
