# Idunn runtime fixtures

Written by the Rust owner, not by Heimdall's tests. Copied byte for byte from CultLib
`217a9480`, `packages/cultnet-ts/test/fixtures/idunn-runtime/web` (`expected.cc`,
`activation.cc`, `activation-key.seed`, `provider-identity.credential`) and that directory's
`machine-id`. CultLib regenerates them with `packages/cultnet-rs/examples/idunn_runtime_fixture.rs`
(its own README has the Yggdrasil command); the provider identity is bound to `machine-id`, so a
test that decodes it supplies that machine id instead of `/etc/machine-id`.

Every key here is a test key. `provider-identity.credential` is the shape Idunn passes on the
presence-identity descriptor: key fields are 32-integer arrays, which only the Rust owner writes.
