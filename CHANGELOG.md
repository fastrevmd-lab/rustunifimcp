# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A committed synthetic fixture set** at `rustunifimcp-core/tests/fixtures/synthetic/`
  (#13). Seventeen of 143 tests needed fixtures captured from a live controller, which
  are deliberately gitignored, so on a fresh clone they printed "SKIPPED: no fixtures"
  and returned early — and CI reported `ok`. Among them were the change-set `diff`,
  `preimage` and `validate` tests, so every green run overstated what had been checked
  on the write path specifically. The synthetic set is hand-written with
  documentation-range addresses, locally administered MACs and zeroed coordinates, and
  is held to the same `scripts/verify-fixtures-scrubbed.sh` gate the recorded sets must
  pass — `gate_passes_on_the_committed_synthetic_fixtures` runs it on every test run.

- **SSDF evidence is wired** (#16). `mecmcp-audit` was a declared dependency imported
  nowhere and the `--ssdf-audit-*` flags were already on the CLI via
  `mecmcp_runtime::cli::Cli`, so they parsed and did nothing — this server emitted none
  of the fleet's change records. With `--ssdf-audit-endpoint` configured the coordinator
  now emits proposal, approval, apply-intent and result-receipt records. Off by default.

- **SSDF evidence is wired** (#16). `mecmcp-audit` was a declared dependency imported
  nowhere and the `--ssdf-audit-*` flags were already on the CLI via
  `mecmcp_runtime::cli::Cli`, so they parsed and did nothing — this server emitted none
  of the fleet's change records. With `--ssdf-audit-endpoint` configured all four now
  land: the coordinator emits the approval records itself, and the server emits the
  proposal on first stage and the apply-intent and result-receipt around the writes.
  The apply is **refused** if the intent cannot be made durable, because an intent that
  survives only in memory proves nothing about a crash; the receipt cannot fail closed,
  since the controller has already acted. The pipeline is flushed with `shutdown()` at
  exit — dropping it stops the worker but deliberately does not spool, so a proposal or
  approval not followed by an apply would otherwise be lost. Off by default.

### Changed

- **`DEFAULT_FIXTURE_VERSION` is now the synthetic set**, and the fixture-gated tests
  no longer skip: the guards are gone, so a missing fixture is a failure rather than a
  silent pass. `fixtures_available()` is replaced by `recorded_fixtures_available()`,
  which only the version matrix and the scrub gate's live check consult — a hand-written
  fixture is evidence about the parsers and nothing at all about controller drift, so
  `tests/version_matrix.rs` excludes it from the recorded versions.
- **`every_resource_kind_has_a_parser_wired` now runs over every fixture set present**,
  so a developer holding a live capture still exercises the parsers against real data
  while CI exercises them against the synthetic set. A recorded version with an
  `.absent` marker for a kind is skipped for that kind — recording a 404 is how the
  matrix asserts drift, and it must not break the parser test — while the synthetic
  set is required to carry every kind.
- Two assertions pinned to the 10.5.67 capture's exact DHCP-reservation count are now
  stated as relationships — strictly fewer than the total, and not zero. The count made
  the committed set carry 46 reservations to satisfy a test that is about the filter
  being active.

- **The change-set store is now `mecmcp-changeset`'s coordinator** (#16). It was a
  persisted `HashMap` with `insert` / `get` / `remove` and no state machine, so three
  protections the rest of the fleet spent three mecmcp minors acquiring were absent
  here: claim-before-apply (two concurrent applies could both observe `Approved` and
  both proceed), the transition policy (any field could be written over any other), and
  preview-bound approval (an approval referenced no preview at all). None of that is
  reimplemented — `insert_change_set`, `approve_change_set` / `waive_approval`,
  `claim_change_set_for_apply` and `update_change_set_from` replace the map, and
  `--approval-timeout-secs` now configures the coordinator's approval TTL, which is
  what actually expires an approval.
- **`unifi_get_change_set` reports the lifecycle's state** rather than a string inferred
  from which fields happen to be populated. `approved` and `pending` used to be derived
  from whether an approver was set, which cannot distinguish an expired approval or a
  cancelled set from a pending one. It also returns the plan digest, the pre-image
  fingerprint, the approval expiry and the preview.
- **A change set can no longer be staged into after approval.** Staging rewrites the
  plan and the digest an approval binds to, so allowing it would let a reviewed plan be
  swapped for an unreviewed one with the approval still attached.
- **`unifi_apply_change_set` records `Applied` only when every write landed** (and for
  an apply that landed but could not be re-read to confirm it, which did apply). A
  partial apply is `Failed`: a record claiming a change landed when only some of it did
  is worse than one an operator has to go and read.
- **The per-mutation apply breakdown is now an audit event**
  (`event = unifi_change_set_applied`) rather than a field on the stored change set. It
  has no home on `ChangeSetRecord`, which is `deny_unknown_fields`, and the shared
  crate's `OperationRecord` was the wrong container: its non-terminal states make every
  later operation on the device refuse as unreconciled, which is right for a vendor
  whose commit either lands or does not and would wedge this one, where a partial apply
  is routine and no tool exists to clear it. The state file holds state; what happened
  is an event.
- Change-set ids are now 64 hex characters, which is what the shared lifecycle validates
  against. The old `cs-<uuid>` form is refused by it.
- **`unifi_approve_change_set` takes an optional `expected_digest`.** Supplying the plan
  digest the approver read is what makes the approval attest to a specific plan: without
  it the lifecycle's digest check compares the stored value with itself, and the approval
  covers whatever the record holds when the call lands.

- **`kind=firewall_policy` now returns the whole policy** from `unifi_get_resource`
  and `unifi_list_resources` (#11). The projection kept six summary fields and dropped
  `source`, `destination`, `protocol`, ports, `schedule` and `connection_state_type` —
  everything that makes a policy mean anything — so an existing policy could not be
  read and adapted into a new one. `FirewallPolicy` now carries the remaining fields
  verbatim and round-trips losslessly.

### Removed

- `mecmcp-job` and `mecmcp-policy` from `[workspace.dependencies]`. Declared, imported
  nowhere, and no plausible use here. `mecmcp-audit` moves from the core crate, which
  never imported it, to the binary, which is where the recorder is built.

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
  shape" prefix that made a lookup miss read like a parse failure. A policy naming a
  zone the same change set deletes is now refused too — apply runs the staged writes
  in order, so the live list still has a zone that will be gone by the time the policy
  lands. That check follows staging order and runs against the *effective* policy, not
  the staged fragment: a Private v2 update is a partial write the client overlays on
  the live resource, so a fragment touching only `enabled` still applies a policy
  carrying the live zones, a second fragment lands on the result of the first, and a
  non-object body changes nothing at all. Both failing orderings are reported with the
  ordering named as the fix.
- **Change-set tools now refuse a controller that does not own the change set.** Every
  one of the seven took a `controller` argument and used it to pick the client without
  ever comparing it to the controller the set was created against, so a set planned
  against one controller could be validated — and applied — against another.

### Upgrading

**The change-set state file is not carried forward.** LXC 981 `prod-unifimcp` writes
`/var/lib/unifimcp/changesets.json`; the new binary refuses to start on a file written by
the old store and names the change sets in it. Move the file aside and re-plan them.

They are deliberately not converted: an approval is now bound to the digest of the
preview its approver read, and the old records have no preview, so carrying one across
would mint an approval over text nobody saw — exactly what preview binding exists to
prevent. Re-planning also re-reads the controller rather than trusting a pre-image of
unknown age.

Two behaviour changes that are easier to read here than to discover:

- **`--approval-timeout-secs` now runs from staging, not from approval.** It configures
  the coordinator's approval TTL, and the deadline is stamped when the change set is
  written — the first `unifi_stage_change`. Apply checks it through `change_set_status`,
  and then against the deadline on the record the claim returns. Neither upstream gate
  covers it: `claim_change_set_for_apply` checks the state and not the clock, and
  `change_set_status` applies the approval TTL only to a `Planned` record — so an
  ordinary two-person approval granted inside the window and applied long after it
  would otherwise still reach the controller. The check is after the claim because the
  claim is what serialises; a pre-claim check alone is a check-then-act race. The packaged default of 300 seconds therefore bounds the whole
  plan-review-apply round. That also bounds the age of the pre-image the plan was built
  against, which is the point, but it is a shorter window than the old code enforced.
- **One pending change set per principal per controller.** A second
  `unifi_create_change_set` on the same controller by the same token is refused until
  the first reaches an outcome or is cancelled.
- **`unifi_create_change_set` returns a draft, not a stored change set.** The
  coordinator's persistence layer refuses to load a state file containing a change set
  with no actions, so writing an empty plan would make the whole store unloadable at the
  next restart — a fault no test run can see, because nothing in one restarts. The
  change set is created on the first `unifi_stage_change`. A draft is held in memory,
  reports `state: "draft"` from `unifi_get_change_set`, lapses with the approval window,
  and is lost on restart along with nothing.
- **`unifi_create_change_set` refuses a description too large for the preview**, which
  would otherwise mint an id that could never become a change set: the description is
  stored inside the preview, so every first stage would rebuild it and be refused after
  the controller reads.
- **A plan is checked against the configured ceilings at stage.** Neither
  `insert_change_set` nor `update_change_set` consults them — only `create_change_set`
  does, which this server cannot use — while the load path enforces a structural cap of
  64 actions. Staging past the limit would persist and then refuse to reload.

Two smaller things about the state file. The coordinator reads it through the workspace's
hardened reader, so a group- or world-readable file is a startup failure with a `chmod`
in the message; the old store wrote 0600 but did not require it. And a **blank** file is
now discarded rather than refused, because the coordinator cannot parse one and an
interrupted first write produces one.

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
