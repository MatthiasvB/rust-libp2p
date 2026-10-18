## 0.5.0-alpha

- Raise MSRV to 1.88.0.
  See [PR 6273](https://github.com/libp2p/rust-libp2p/pull/6273).

- Add `Config` and `Behaviour::with_config`.
  `Config::with_relayed_connections(false)` keeps streams off relayed connections in both directions.
  `Config::with_dialing(false)` makes `Control::open_stream` fail with `io::ErrorKind::NotConnected` instead of dialing.
  The defaults keep the previous behaviour.
  See [PR XXXX](https://github.com/libp2p/rust-libp2p/pull/XXXX).

## 0.4.0-alpha

- Garbage-collect deregistered streams when accepting new streams.
  See [PR 5999](https://github.com/libp2p/rust-libp2p/pull/5999).

<!-- Update to libp2p-swarm v0.47.0 -->

## 0.3.0-alpha

- Deprecate `void` crate.
  See [PR 5676](https://github.com/libp2p/rust-libp2p/pull/5676).

<!-- Update to libp2p-core v0.43.0 -->

## 0.2.0-alpha

<!-- Update to libp2p-swarm v0.45.0 -->

## 0.1.0-alpha.1
- Implement Error for `OpenStreamError`.
  See [PR 5169](https://github.com/libp2p/rust-libp2p/pull/5169).

## 0.1.0-alpha

Initial release.
