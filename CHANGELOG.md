# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`unifi_validate_change_set` no longer refuses every zone-based firewall policy**
  (#10). The reference check read its zone list from the change set's pre-image and
  looked for a resource with `_id == "_all_"`, which no controller returns. A create
  records no pre-image at all, so the zone index was empty for exactly the mutations
  that needed checking and every `firewall_policy` create was rejected as referencing
  a zone that did not exist. Validate now fetches the controller's live zone list, and
  only when a staged body names a zone. Three further changes to the same check:
  `destination.zone_id` is checked as well as `source.zone_id`; a zone named by its
  `external_id` reports the `_id` to use instead of claiming the zone is absent; and a
  zone list that cannot be read is a distinct error from a zone that is not there —
  the new `UnifiError::ReferenceNotFound` renders without the "unexpected response
  shape" prefix that made a lookup miss read like a parse failure.

### Changed

- **`kind=firewall_policy` now returns the whole policy** from `unifi_get_resource`
  and `unifi_list_resources` (#11). The projection kept six summary fields and dropped
  `source`, `destination`, `protocol`, ports, `schedule` and `connection_state_type` —
  everything that makes a policy mean anything — so an existing policy could not be
  read and adapted into a new one. `FirewallPolicy` now carries the remaining fields
  verbatim and round-trips losslessly.

## [0.2.0] - 2026-09-01

This is a **minor version** because it adds the reproducible release path (Dockerfile
and GitHub Actions workflow) that v0.1.0 lacked. The binary running on LXC 981 at
v0.1.0's tag date was built and installed by hand, predating the GitHub release artifact
by fifteen hours. v0.2.0 closes that gap.

### Added

- **Dockerfile** for reproducible multi-stage builds, producing a distroless runtime
  image with no shell, no package manager, and only the server binary and libc.
  Builder and runtime both pinned to Debian 13 (trixie) to ensure glibc compatibility
  with LXC 981.
- **GitHub Actions `release-image.yml` workflow** to build and push container images
  to `ghcr.io/fastrevmd-lab/rustunifimcp` on version tags.
- **CI workflow** with format, clippy, build, and test steps.
- **Security workflow** with gitleaks, cargo-audit, and cargo-deny checks.
- **Dependabot** configuration for cargo and github-actions ecosystems, with
  mecmcp-* and dtolnay/rust-toolchain ignores.
- **`deny.toml`** for supply-chain checks.
- **`CLAUDE.md`** documenting that LXC 981 `prod-unifimcp` must run with
  `--lab-mode` to expose write tools in the single-operator homelab deployment.
- **gitleaks allowlist** (`.gitleaks.toml`) for the fixture-scrub gate's two
  synthetic credentials in `rustunifimcp-core/tests/fixture_scrub_gate.rs`.

### Changed

- Re-pinned the `mecmcp-*` crates from `v0.20.0` to `v0.23.0`. 0.23.0 binds a
  change set's preview digest into its approval digest, so an approval now
  vouches for the exact preview a reviewer saw.
- **`Atomicity` is now re-exported from `mecmcp-changeset`** instead of being
  defined locally. A local duplicate would be a distinct type that shared code
  could not accept, defeating the point of declaring the guarantee.
  `UnifiTransaction::atomicity()` returns `Atomicity::live_writes()`.
- Updated `rcgen` from 0.14.9 to 0.14.10.

### Fixed

- **Three changeset tests now guard on `fixtures_available()`** instead of
  calling `fixture()` directly. The tests pass on a developer machine but
  failed on a fresh clone because `rustunifimcp-core/tests/fixtures/*/` is
  gitignored. A missing fixture is now an un-run test, not a failing one.
- **`a_top_level_api_key_is_rejected_at_load_time` is no longer ignored.**
  It covers a security invariant — an `api_key` at the inventory envelope level
  must not be silently accepted — and was the only test for it. Enabled because
  `CanonicalEnvelope` in mecmcp 0.23.0 now carries `#[serde(deny_unknown_fields)]`.

[unreleased]: https://github.com/fastrevmd-lab/rustunifimcp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/fastrevmd-lab/rustunifimcp/releases/tag/v0.2.0
