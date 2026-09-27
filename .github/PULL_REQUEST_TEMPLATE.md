## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --locked -- -D warnings` passes
- [ ] Tests added or updated for this change, and they fail against the old code
- [ ] `cargo audit` and `cargo deny check bans sources` are clean, or any new advisory/exception is called out below
- [ ] This PR does not touch, or does not weaken, any UniFi controller write / change-control code path — or if it does, that's explained below
- [ ] Any fixture added or changed is synthetic and passes `scripts/verify-fixtures-scrubbed.sh`
- [ ] No secrets, credentials, real hostnames, controller serials, MAC addresses, or real device/site configs in code, tests, fixtures, or this description
- [ ] No new telemetry, analytics, or outbound network call added
- [ ] If this touches a path that can act on a controller: deterministic code decides, not a model output

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
