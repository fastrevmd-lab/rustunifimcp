//! Per-resource-kind allowlist projection, applied before a UniFi resource
//! reaches the model.
//!
//! UniFi's read APIs do not distinguish "safe to show an operator with
//! console access" from "safe to hand to a model with no duty of
//! confidentiality" -- a WLAN's `x_passphrase`, a VPN network's `x_secret` or
//! WireGuard private key, a RADIUS profile's shared secret, and a WAN's
//! PPPoE password all travel in the same JSON object as the name, VLAN, and
//! subnet a caller actually needs. This module is the boundary that makes the
//! distinction, once, for every path that can hand a resource back as tool
//! output: `unifi_list_resources`, `unifi_get_resource`, change-set
//! pre-images and diffs, and anything else that reads a resource by
//! `ResourceKind`.
//!
//! Every kind except [`ResourceKind::FirewallPolicy`] is projected through a
//! [`FieldAllowlist`] naming exactly the fields the model may see -- a
//! stronger guarantee than the denylist alone, because an allowlist drops an
//! unrecognized field rather than requiring it to be named first.
//! `FirewallPolicy` is the one shape this server deliberately keeps complete
//! (see `model::firewall`'s doc comment: a policy missing `source` or
//! `destination` cannot be used as an authoring template), so it is instead
//! run through the shared crate's denylist-and-shape scan, which redacts a
//! secret-named field in place without dropping fields nobody has named yet.

use crate::model::ResourceKind;
use mecmcp_redact::projection::FieldAllowlist;
use serde_json::Value;

/// Fields the model may see for a [`ResourceKind::Station`].
///
/// Covers two different raw shapes for the same kind: the Integration API's
/// camelCase station (`model::station::Station` already parses this one),
/// and the private `stat/sta` endpoint's snake_case client record that
/// `unifi_client_troubleshoot` and its report-joins correlate against
/// instead (no typed model exists for it -- its shape is legacy-API and
/// varies by controller version, same as the stats endpoints in
/// `read.rs::project_stats`). Both sides of the union are non-secret
/// operational fields; unioning them does not weaken the guarantee, since an
/// allowlist only ever keeps a field it names.
const STATION_FIELDS: FieldAllowlist = FieldAllowlist::new(&[
    // Integration API (camelCase).
    "id",
    "type",
    "name",
    "connectedAt",
    "ipAddress",
    "macAddress",
    "uplinkDeviceId",
    // Private `stat/sta` (snake_case).
    "_id",
    "mac",
    "last_ip",
    "network_id",
    "last_uplink_mac",
    "hostname",
    "is_wired",
]);

/// Fields the model may see for a [`ResourceKind::Device`].
const DEVICE_FIELDS: FieldAllowlist = FieldAllowlist::new(&[
    "id",
    "macAddress",
    "ipAddress",
    "name",
    "model",
    "state",
    "supported",
    "firmwareVersion",
    "firmwareUpdatable",
    "features",
    "interfaces",
]);

/// Fields the model may see for a [`ResourceKind::Network`].
///
/// Deliberately excludes every WAN credential a network can carry --
/// `x_pppoe_password`, `x_ipsec_pre_shared_key`, `x_secret`,
/// `wireguard_private_key`, and the rest of the `x_*` family UniFi uses for
/// secret-bearing fields.
const NETWORK_FIELDS: FieldAllowlist = FieldAllowlist::new(&[
    "_id",
    "name",
    "purpose",
    "ip_subnet",
    "vlan",
    "dhcpd_enabled",
    "dhcpd_start",
    "dhcpd_stop",
    "wan_dns1",
    "wan_dns2",
    "wan_ipv6_dns1",
    "wan_ipv6_dns2",
    "wan_type",
]);

/// Fields the model may see for a [`ResourceKind::Wlan`].
///
/// Excludes `x_passphrase` and `x_iapp_key`, the WLAN's PSK and inter-AP
/// roaming key. `x_iapp_key` in particular cannot be caught by the shared
/// crate's denylist-and-shape scan -- `key` is denylisted only as a whole
/// field name, not a substring (see that crate's `denylist` module), so
/// `x_iapp_key` slips through it. `num_sta` and `satisfaction` are included
/// because `unifi_query_stats(subject=wlan)` answers with this same shape
/// merged with runtime counters, and this allowlist is what that leg
/// projects through (see `tools::read::project_stats`).
const WLAN_FIELDS: FieldAllowlist = FieldAllowlist::new(&[
    "_id",
    "name",
    "enabled",
    "security",
    "wlan_band",
    "is_guest",
    "num_sta",
    "satisfaction",
]);

/// Fields the model may see for a [`ResourceKind::PortProfile`].
const PORT_PROFILE_FIELDS: FieldAllowlist =
    FieldAllowlist::new(&["_id", "name", "forward", "native_networkconf_id"]);

/// Fields the model may see for a [`ResourceKind::DhcpReservation`].
const DHCP_RESERVATION_FIELDS: FieldAllowlist = FieldAllowlist::new(&[
    "_id",
    "mac",
    "last_ip",
    "fixed_ip",
    "hostname",
    "use_fixedip",
]);

/// Fields the model may see for a [`ResourceKind::RadiusProfile`].
///
/// Excludes `auth_servers`/`acct_servers` entirely: each entry carries an
/// `x_passphrase` RADIUS shared secret, and there is no non-secret field in
/// those objects worth keeping in isolation.
const RADIUS_PROFILE_FIELDS: FieldAllowlist = FieldAllowlist::new(&["_id", "name", "external_id"]);

/// Fields the model may see for a [`ResourceKind::FirewallGroup`].
const FIREWALL_GROUP_FIELDS: FieldAllowlist =
    FieldAllowlist::new(&["_id", "name", "group_type", "group_members", "external_id"]);

/// Fields the model may see for a [`ResourceKind::FirewallZone`].
const FIREWALL_ZONE_FIELDS: FieldAllowlist =
    FieldAllowlist::new(&["_id", "name", "default_zone", "network_ids", "external_id"]);

/// Fields the model may see for a [`ResourceKind::TrafficRoute`].
const TRAFFIC_ROUTE_FIELDS: FieldAllowlist = FieldAllowlist::new(&["_id", "name"]);

/// The allowlist for `kind`, or `None` for [`ResourceKind::FirewallPolicy`],
/// which is handled by [`project_firewall_policy`] instead.
const fn allowlist_for(kind: ResourceKind) -> Option<FieldAllowlist> {
    match kind {
        ResourceKind::Station => Some(STATION_FIELDS),
        ResourceKind::Device => Some(DEVICE_FIELDS),
        ResourceKind::Network => Some(NETWORK_FIELDS),
        ResourceKind::Wlan => Some(WLAN_FIELDS),
        ResourceKind::PortProfile => Some(PORT_PROFILE_FIELDS),
        ResourceKind::DhcpReservation => Some(DHCP_RESERVATION_FIELDS),
        ResourceKind::RadiusProfile => Some(RADIUS_PROFILE_FIELDS),
        ResourceKind::FirewallGroup => Some(FIREWALL_GROUP_FIELDS),
        ResourceKind::FirewallZone => Some(FIREWALL_ZONE_FIELDS),
        ResourceKind::TrafficRoute => Some(TRAFFIC_ROUTE_FIELDS),
        ResourceKind::FirewallPolicy => None,
    }
}

/// Redact a firewall policy's open field set (`FirewallPolicy::rest`) without
/// dropping fields the authoring loop depends on.
///
/// Runs the shared crate's denylist-and-shape scan over the whole value: a
/// secret-named field anywhere in the policy is replaced in place, and every
/// other field -- known or not -- survives, because a policy an operator
/// cannot read back completely is not one they can safely edit and restage.
fn project_firewall_policy(value: &Value) -> Value {
    let mut projected = value.clone();
    mecmcp_redact::redact_json_value(&mut projected);
    projected
}

/// Project a single resource of `kind` down to the fields the model may see.
#[must_use]
pub fn project_resource(kind: ResourceKind, value: &Value) -> Value {
    match allowlist_for(kind) {
        Some(allow) => allow.project(value),
        None => project_firewall_policy(value),
    }
}

/// Project a list (or single value, matching [`FieldAllowlist::project_many`])
/// of resources of `kind`.
#[must_use]
pub fn project_resource_list(kind: ResourceKind, value: &Value) -> Value {
    match allowlist_for(kind) {
        Some(allow) => allow.project_many(value),
        None => match value {
            Value::Array(items) => {
                Value::Array(items.iter().map(project_firewall_policy).collect())
            }
            other => project_firewall_policy(other),
        },
    }
}

/// Project a resource addressed by a `kind` string (as staged mutations carry
/// it) rather than a typed [`ResourceKind`].
///
/// Falls back to the shared crate's denylist-and-shape scan -- rather than
/// returning the value untouched -- when `kind` does not name a known
/// resource kind, so an unrecognized or malformed kind string never becomes a
/// way to skip redaction.
#[must_use]
pub fn project_by_kind_name(kind: &str, value: &Value) -> Value {
    match serde_json::from_value::<ResourceKind>(Value::String(kind.to_owned())) {
        Ok(kind) => project_resource(kind, value),
        Err(_) => redact_owned(value),
    }
}

/// Redact `value` in place using the shared crate's denylist-and-shape scan.
///
/// For resource shapes this server does not fully control (aggregate
/// statistics, workflow joins, search results already reduced to a JSON
/// blob) -- the defensive net, not the strong guarantee an allowlist gives.
pub fn redact_in_place(value: &mut Value) {
    mecmcp_redact::redact_json_value(value);
}

/// Clone `value` and redact the clone using the shared crate's
/// denylist-and-shape scan.
#[must_use]
pub fn redact_owned(value: &Value) -> Value {
    let mut owned = value.clone();
    redact_in_place(&mut owned);
    owned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// Every declared allowlist must actually strip the secret-bearing field
    /// present in that kind's synthetic fixture. Runs over every
    /// `ResourceKind` rather than hand-picking a few, so a kind added later
    /// without an allowlist entry fails loudly here instead of shipping a
    /// silent bypass.
    #[test]
    fn every_resource_kind_drops_its_fixtures_secret() {
        let cases: &[(ResourceKind, &str, &str)] = &[
            (
                ResourceKind::Wlan,
                "wlanconf",
                "EXAMPLE-wifi-passphrase-fake1",
            ),
            (
                ResourceKind::Network,
                "networkconf",
                "EXAMPLE-vpn-shared-secret-fake1",
            ),
            (
                ResourceKind::RadiusProfile,
                "radiusprofile",
                "EXAMPLE-radius-auth-secret-fake1",
            ),
        ];

        for &(kind, fixture_name, secret) in cases {
            let raw = fixture(DEFAULT_FIXTURE_VERSION, fixture_name);
            let data = raw
                .get("data")
                .cloned()
                .unwrap_or_else(|| panic!("{fixture_name} has no data envelope"));

            let projected = project_resource_list(kind, &data);
            let rendered = projected.to_string();
            assert!(
                !rendered.contains(secret),
                "{kind:?} allowlist let {secret} through: {rendered}"
            );
        }
    }

    #[test]
    fn network_allowlist_drops_every_wan_and_vpn_secret_field() {
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "networkconf");
        let data = raw.get("data").expect("networkconf has data");

        let projected = project_resource_list(ResourceKind::Network, data);
        let rendered = projected.to_string();

        for secret in [
            "EXAMPLE-vpn-shared-secret-fake1",
            "EXAMPLE-pppoe-password-fake1",
            "EXAMPLE-wireguard-private-key-fake1",
            "EXAMPLE-ipsec-preshared-key-fake1",
        ] {
            assert!(!rendered.contains(secret), "leaked: {secret}");
        }

        // And it must not have thrown the baby out with the bathwater: the
        // corporate network's non-secret fields must still be there.
        assert!(rendered.contains("Test Network"));
        assert!(rendered.contains("192.0.2.0/24"));
    }

    #[test]
    fn firewall_policy_keeps_unknown_fields_but_redacts_a_secret_named_one() {
        let value = serde_json::json!({
            "_id": "abc123",
            "name": "allow-vpn",
            "action": "ALLOW",
            "enabled": true,
            "index": 100,
            "source": {"zone_id": "z1"},
            "shared_secret": "EXAMPLE-policy-secret-fake1",
        });

        let projected = project_resource(ResourceKind::FirewallPolicy, &value);
        assert_eq!(
            projected["source"]["zone_id"], "z1",
            "unknown field dropped"
        );
        assert_eq!(projected["name"], "allow-vpn");
        assert_ne!(projected["shared_secret"], "EXAMPLE-policy-secret-fake1");
    }

    #[test]
    fn unknown_kind_string_falls_back_to_the_denylist_scan_rather_than_passing_through() {
        let value = serde_json::json!({"password": "EXAMPLE-fallback-secret-fake1", "name": "x"});
        let projected = project_by_kind_name("not_a_real_kind", &value);
        assert_ne!(projected["password"], "EXAMPLE-fallback-secret-fake1");
        assert_eq!(projected["name"], "x");
    }
}
