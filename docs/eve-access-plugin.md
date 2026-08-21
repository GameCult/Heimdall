# Heimdall Eve Access Boundary

## Objective

Let Eve applications request authentication without learning provider OAuth,
claim, entitlement, or completion mechanics. The browser can render the access
gate and carry one opaque attempt handle; it cannot grant access.

## Authority map

- **Owner:** Heimdall owns OAuth attempts, provider callbacks, entitlement
  evaluation, completion redemption, and claim issuance.
- **Inputs:** a signed private CultNet operation from an allowlisted app binding,
  provider callback evidence, and Heimdall-owned auth/control-plane state.
- **Outputs:** a navigation receipt for `heimdall.auth.begin`, or an encrypted
  single-use completion for `heimdall.auth.complete`.
- **Derived state:** Eve access-gate components, plugin projections, Odin route
  metadata, and browser status are projections. They never grant access.
- **Forbidden writers:** browsers, Eve lowerers, Odin, Hermodr, and host apps may
  not create or complete Heimdall attempts, evaluate entitlements, or mint
  claims. Host apps may create only their own local sessions after verification.
- **Shared paths:** HTTP OAuth starts and private CultNet starts use the same
  state-token builder; all provider callbacks use the same callback handler and
  completion store; all redemption consumes the same single-use completion.
- **Cut line:** the private command plane is loopback-only and authenticated by
  the existing app secret. Public CultMesh receives plugin and route metadata,
  never claims, tokens, nonces, secrets, or attempt contents.

The access plugin owns representation and browser navigation semantics. It does
not accept provider commands or mutate authentication state. Its `describe`,
`validate`, and `project` ABI is pure; app commands still cross the provider's
advertised command boundary.
