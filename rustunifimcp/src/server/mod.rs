//! The MCP server handler.

use crate::changeset_store::{ChangeSet, ChangeSetStore};
use mecmcp_auth::NoGrant;
use mecmcp_server::{
    ResultFormat, ResultLimits, authorize_call, caller_from_extensions, filter_tools_for_scope,
    tool_error, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rustunifimcp_core::{
    changeset::{
        Preimage, StagedMutation, State, ZoneIndex, apply_sequentially, check_zone_deletions,
        check_zone_references, diff_against_preimage, referenced_zone_ids, validate_locally,
    },
    client::UnifiClient,
    error::UnifiError,
    inventory::ControllerRegistry,
    model::ResourceKind,
    tools::{WRITE_TOOLS, admin, changeset, ops, read, workflow},
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Empty arguments for parameterless tools.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct NoArgs {}

/// Result size limits for MCP tool responses.
const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

/// Seconds since the Unix epoch.
///
/// A clock before the epoch is not a case worth branching on; it reports 0,
/// which makes every approval look old and therefore expired -- the safe
/// direction for a gate.
fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The UniFi MCP server.
#[derive(Clone)]
pub struct UnifiServer {
    /// Controller inventory.
    registry: Arc<ControllerRegistry>,
    /// Clients per controller. RwLock allows rebuild on SIGHUP.
    clients: Arc<std::sync::RwLock<BTreeMap<String, UnifiClient>>>,
    /// Whether lab mode is enabled.
    lab_mode: bool,
    /// Change-set storage.
    changeset_store: ChangeSetStore,
    /// How long an approval stays usable, in seconds.
    approval_timeout_secs: u64,
    /// Tool router.
    tool_router: ToolRouter<Self>,
}

impl UnifiServer {
    /// Create a new server with the given registry, lab mode setting, and changeset store.
    ///
    /// # Errors
    ///
    /// Returns an error if any client cannot be built.
    pub fn new(
        registry: Arc<ControllerRegistry>,
        lab_mode: bool,
        changeset_store: ChangeSetStore,
        approval_timeout_secs: u64,
    ) -> Result<Self, UnifiError> {
        let clients = Self::build_clients(&registry)?;
        Ok(Self {
            registry,
            clients: Arc::new(std::sync::RwLock::new(clients)),
            lab_mode,
            changeset_store,
            approval_timeout_secs,
            tool_router: Self::unifi_tool_router(),
        })
    }

    /// Build HTTP clients for all controllers in the registry.
    fn build_clients(
        registry: &ControllerRegistry,
    ) -> Result<BTreeMap<String, UnifiClient>, UnifiError> {
        let mut clients = BTreeMap::new();
        for name in registry.names() {
            let controller = registry.get(&name)?;
            clients.insert(name.clone(), UnifiClient::new(controller)?);
        }
        Ok(clients)
    }

    /// Rebuild all clients from the current registry state.
    ///
    /// This is called on SIGHUP after the registry has been reloaded, so that
    /// configuration changes (endpoint, credential, allow_private_api) take
    /// effect without restarting the server.
    ///
    /// # Errors
    ///
    /// Returns an error if any client cannot be built. On error, the previous
    /// clients are retained.
    pub fn rebuild_clients(&self) -> Result<usize, UnifiError> {
        let new_clients = Self::build_clients(&self.registry)?;
        let count = new_clients.len();

        let mut clients = self
            .clients
            .write()
            .map_err(|_| UnifiError::Malformed("clients lock poisoned".to_owned()))?;

        *clients = new_clients;
        Ok(count)
    }

    /// Get a reference to the client for a controller.
    ///
    /// Returns an owned client since we cannot return a reference that outlives
    /// the RwLock guard. UnifiClient is cheap to clone (Arc-wrapped internals).
    fn client_for(&self, controller: &str) -> Result<UnifiClient, Box<CallToolResult>> {
        let clients = self
            .clients
            .read()
            .map_err(|_| Box::new(tool_error("clients lock poisoned".to_owned())))?;

        clients
            .get(controller)
            .cloned()
            .ok_or_else(|| Box::new(tool_error(format!("unknown controller: {controller}"))))
    }

    /// Recover the caller from the request context.
    fn caller(context: &RequestContext<RoleServer>) -> Option<mecmcp_auth::CallerCtx<NoGrant>> {
        caller_from_extensions::<NoGrant>(&context.extensions).cloned()
    }

    /// Fetch a change set, refusing it if the caller named another controller.
    ///
    /// A change set records the controller it was created against, and its
    /// mutations and pre-image are meaningful only there. Every change-set tool
    /// also takes a `controller` argument and used it to pick the client
    /// without ever comparing the two, so a set planned against one controller
    /// could be validated -- and applied -- against another: resource ids that
    /// exist on neither, or worse, ids that happen to exist on both and name
    /// different things.
    fn change_set_for(
        &self,
        change_set_id: &str,
        controller: &str,
    ) -> Result<ChangeSet, Box<CallToolResult>> {
        let change_set = match self.changeset_store.get(change_set_id) {
            Ok(Some(set)) => set,
            Ok(None) => {
                return Err(Box::new(tool_error(format!(
                    "change set not found: {change_set_id}"
                ))));
            }
            Err(e) => {
                return Err(Box::new(tool_error(format!(
                    "failed to retrieve change set: {e}"
                ))));
            }
        };

        if change_set.controller != controller {
            return Err(Box::new(tool_error(format!(
                "change set {change_set_id} targets controller '{}', not '{controller}'",
                change_set.controller
            ))));
        }

        Ok(change_set)
    }
}

#[tool_router(router = unifi_tool_router, vis = "pub(crate)")]
impl UnifiServer {
    #[tool(
        name = "unifi_list_resources",
        description = "List UniFi resources by type and site"
    )]
    async fn unifi_list_resources(
        &self,
        Parameters(args): Parameters<read::ListResourcesArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_list_resources",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::list_resources(&client, &args).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_get_resource",
        description = "Get a specific UniFi resource by type and id"
    )]
    async fn unifi_get_resource(
        &self,
        Parameters(args): Parameters<read::GetResourceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_get_resource",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::get_resource(&client, &args).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_query_stats",
        description = "Query statistics for UniFi resources"
    )]
    async fn unifi_query_stats(
        &self,
        Parameters(args): Parameters<read::QueryStatsArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_query_stats",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::query_stats(&client, &args).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_search",
        description = "Search UniFi resources with filters"
    )]
    async fn unifi_search(
        &self,
        Parameters(args): Parameters<read::SearchArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_search",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::search(&client, &args).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_list_sites",
        description = "List all sites on a UniFi controller"
    )]
    async fn unifi_list_sites(
        &self,
        Parameters(args): Parameters<read::ListSitesArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_list_sites",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::list_sites(&client, &args).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_list_controllers",
        description = "List all configured UniFi controllers"
    )]
    async fn unifi_list_controllers(
        &self,
        _params: Parameters<NoArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) =
            authorize_call(caller.as_ref(), "unifi_list_controllers", None, WRITE_TOOLS)
        {
            return tool_error(error);
        }

        match admin::unifi_list_controllers(&self.registry).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifimcp_status",
        description = "Get server status and controller connectivity"
    )]
    async fn unifimcp_status(
        &self,
        _params: Parameters<NoArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(caller.as_ref(), "unifimcp_status", None, WRITE_TOOLS) {
            return tool_error(error);
        }

        match admin::unifimcp_status(&self.registry, self.lab_mode).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_add_controller",
        description = "Add a controller to the inventory (fails in production - edit config instead)"
    )]
    async fn unifi_add_controller(
        &self,
        Parameters(_args): Parameters<NoArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) =
            authorize_call(caller.as_ref(), "unifi_add_controller", None, WRITE_TOOLS)
        {
            return tool_error(error);
        }

        match admin::unifi_add_controller("", "", "", None, None).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_device_action",
        description = "Execute an operational action on a device (restart, locate, adopt, upgrade, port_action)"
    )]
    async fn unifi_device_action(
        &self,
        Parameters(args): Parameters<ops::DeviceActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_device_action",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match ops::device_action(args, &client).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_client_action",
        description = "Execute an operational action on a client (block, unblock, reconnect, authorize, limit_bandwidth)"
    )]
    async fn unifi_client_action(
        &self,
        Parameters(args): Parameters<ops::ClientActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_client_action",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match ops::client_action(args, &client).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_backup_action",
        description = "Execute a backup action (trigger, list, download, validate). `restore` is not an operational action — it is governed by the change-set lifecycle (Phase 6): `unifi_create_change_set` -> `unifi_stage_change` -> `unifi_approve_change_set` -> `unifi_apply_change_set`."
    )]
    async fn unifi_backup_action(
        &self,
        Parameters(args): Parameters<ops::BackupActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_backup_action",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match ops::backup_action(args, &client).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_run_speed_test",
        description = "Run a speed test from the controller"
    )]
    async fn unifi_run_speed_test(
        &self,
        Parameters(args): Parameters<ops::SpeedTestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_run_speed_test",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match ops::run_speed_test(args, &client).await {
            Ok(json) => tool_result(
                Ok::<_, String>(json),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_site_health_report",
        description = "Generate a site health report joining devices, health metrics, and statistics"
    )]
    async fn unifi_site_health_report(
        &self,
        Parameters(args): Parameters<workflow::SiteHealthReportArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_site_health_report",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match workflow::site_health_report(&client, &args).await {
            Ok(report) => tool_result(
                Ok::<_, String>(report),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_topology_report",
        description = "Generate a network topology report joining edges, devices, and networks"
    )]
    async fn unifi_topology_report(
        &self,
        Parameters(args): Parameters<workflow::TopologyReportArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_topology_report",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match workflow::topology_report(&client, &args).await {
            Ok(report) => tool_result(
                Ok::<_, String>(report),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_traffic_flow_report",
        description = "Generate a traffic flow report joining clients, statistics, and top applications"
    )]
    async fn unifi_traffic_flow_report(
        &self,
        Parameters(args): Parameters<workflow::TrafficFlowReportArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_traffic_flow_report",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match workflow::traffic_flow_report(&client, &args).await {
            Ok(report) => tool_result(
                Ok::<_, String>(report),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_firewall_audit",
        description = "Audit firewall policies and zones for common misconfigurations"
    )]
    async fn unifi_firewall_audit(
        &self,
        Parameters(args): Parameters<workflow::FirewallAuditArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_firewall_audit",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match workflow::firewall_audit(&client, &args).await {
            Ok(report) => tool_result(
                Ok::<_, String>(report),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_client_troubleshoot",
        description = "Troubleshoot a client by correlating association, uplink, and firewall policy"
    )]
    async fn unifi_client_troubleshoot(
        &self,
        Parameters(args): Parameters<workflow::ClientTroubleshootArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_client_troubleshoot",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match workflow::client_troubleshoot(&client, &args).await {
            Ok(report) => tool_result(
                Ok::<_, String>(report),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    // Change-set lifecycle tools (Phase 6)
    // Full implementation deferred to change-set integration

    #[tool(
        name = "unifi_create_change_set",
        description = "Creates a new change set with a fingerprint snapshot of current running configuration"
    )]
    async fn unifi_create_change_set(
        &self,
        Parameters(args): Parameters<changeset::CreateChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_create_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let creator = caller
            .as_ref()
            .map(|c| c.token_name.clone())
            .unwrap_or_else(|| "unknown".to_owned());

        let id = format!("cs-{}", uuid::Uuid::new_v4());

        let (approver, approval_waiver) = if self.lab_mode {
            (None, Some("lab-mode".to_owned()))
        } else {
            (None, None)
        };

        let change_set = ChangeSet {
            approved_at: None,
            id: id.clone(),
            controller: args.controller.clone(),
            description: args.description,
            creator,
            approver,
            approval_waiver,
            preimage: None,
            mutations: Vec::new(),
            outcome: None,
        };

        if let Err(e) = self.changeset_store.insert(change_set) {
            return tool_error(format!("failed to store change set: {e}"));
        }

        let result = serde_json::json!({
            "change_set_id": id,
            "controller": args.controller,
            "state": "pending",
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "unifi_stage_change",
        description = "Stages one or more changes into an existing change set"
    )]
    async fn unifi_stage_change(
        &self,
        Parameters(args): Parameters<changeset::StageChangeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_stage_change",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        // Retrieve the change set
        let mut change_set = match self.change_set_for(&args.change_set_id, &args.controller) {
            Ok(set) => set,
            Err(result) => return *result,
        };

        // Get the client
        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // Convert MutationSpec to StagedMutation
        let mut new_mutations = Vec::new();
        for spec in args.mutations {
            let mutation = match spec {
                changeset::MutationSpec::Create { kind, body } => {
                    StagedMutation::create(kind, body)
                }
                changeset::MutationSpec::Update { kind, id, body } => {
                    StagedMutation::update(kind, id, body)
                }
                changeset::MutationSpec::Delete { kind, id } => StagedMutation::delete(kind, id),
                changeset::MutationSpec::Restore { backup_id } => {
                    StagedMutation::restore(backup_id)
                }
            };
            new_mutations.push(mutation);
        }

        // Capture pre-image for the new mutations
        let all_mutations: Vec<_> = change_set
            .mutations
            .iter()
            .chain(new_mutations.iter())
            .cloned()
            .collect();
        let preimage = match Preimage::capture_preimage(&client, &all_mutations).await {
            Ok(p) => p,
            Err(e) => return tool_error(format!("failed to capture pre-image: {e}")),
        };

        // Update the change set
        change_set.mutations.extend(new_mutations);
        change_set.preimage = Some(preimage);

        if let Err(e) = self.changeset_store.insert(change_set.clone()) {
            return tool_error(format!("failed to update change set: {e}"));
        }

        let result = serde_json::json!({
            "change_set_id": change_set.id,
            "staged_count": change_set.mutations.len(),
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "unifi_diff_change_set",
        description = "Returns a diff showing what applying the change set would do"
    )]
    async fn unifi_diff_change_set(
        &self,
        Parameters(args): Parameters<changeset::DiffChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_diff_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        // Retrieve the change set
        let change_set = match self.change_set_for(&args.change_set_id, &args.controller) {
            Ok(set) => set,
            Err(result) => return *result,
        };

        let preimage = match &change_set.preimage {
            Some(p) => p,
            None => {
                return tool_error("change set has no pre-image; stage at least one change first");
            }
        };

        let diff = match diff_against_preimage(preimage, &change_set.mutations) {
            Ok(d) => d,
            Err(e) => return tool_error(format!("failed to compute diff: {e}")),
        };

        let result = serde_json::json!({
            "change_set_id": change_set.id,
            "changes": diff.changes,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "unifi_validate_change_set",
        description = "Validates the change set as far as possible without applying it"
    )]
    async fn unifi_validate_change_set(
        &self,
        Parameters(args): Parameters<changeset::ValidateChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_validate_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        // Retrieve the change set
        let change_set = match self.change_set_for(&args.change_set_id, &args.controller) {
            Ok(set) => set,
            Err(result) => return *result,
        };

        let preimage = match &change_set.preimage {
            Some(p) => p,
            None => {
                return tool_error("change set has no pre-image; stage at least one change first");
            }
        };

        // Validate locally
        if let Err(e) = validate_locally(preimage, &change_set.mutations) {
            return tool_error(format!("local validation failed: {e}"));
        }

        // A zone this set deletes must not be left referenced by anything else
        // in the set. Checked first because it needs no controller round trip:
        // it compares the set against itself and against the pre-image.
        if let Err(e) = check_zone_deletions(preimage, &change_set.mutations) {
            return tool_error(format!("reference check failed: {e}"));
        }

        // Referential integrity is checked against the controller's live zone
        // list, not the pre-image. The pre-image records nothing for a create,
        // and it was being searched for a resource with `_id == "_all_"` that
        // no controller ever returns -- so the zone index was empty for every
        // `firewall_policy` create and each one was refused as referencing a
        // zone that did not exist. Fetch only when a staged body names a zone,
        // so a change set that touches no firewall does not start depending on
        // the firewall surface being reachable.
        if !referenced_zone_ids(&change_set.mutations).is_empty() {
            let client = match self.client_for(&args.controller) {
                Ok(client) => client,
                Err(result) => return *result,
            };

            let zone_args = read::ListResourcesArgs {
                controller: args.controller.clone(),
                kind: ResourceKind::FirewallZone,
                site: None,
                limit: None,
                offset: None,
            };

            let raw = match read::list_resources(&client, &zone_args).await {
                Ok(raw) => raw,
                Err(e) => {
                    return tool_error(format!(
                        "could not read the firewall zone list from controller '{}', so zone \
                         references cannot be checked: {e}",
                        args.controller
                    ));
                }
            };

            let zones = match ZoneIndex::from_zone_list(&raw) {
                Ok(zones) => zones,
                Err(e) => {
                    return tool_error(format!(
                        "could not read the firewall zone list from controller '{}', so zone \
                         references cannot be checked: {e}",
                        args.controller
                    ));
                }
            };

            if let Err(e) = check_zone_references(&zones, &change_set.mutations) {
                return tool_error(format!("reference check failed: {e}"));
            }
        }

        let result = serde_json::json!({
            "change_set_id": change_set.id,
            "valid": true,
            "note": "UniFi has no server-side dry-run validation; this is client-side only"
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "unifi_approve_change_set",
        description = "Approves a change set for apply (requires two-person control)"
    )]
    async fn unifi_approve_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApproveChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_approve_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let approver = caller
            .as_ref()
            .map(|c| c.token_name.clone())
            .unwrap_or_else(|| "unknown".to_owned());

        // Retrieve the change set
        let mut change_set = match self.change_set_for(&args.change_set_id, &args.controller) {
            Ok(set) => set,
            Err(result) => return *result,
        };

        // An approval is a statement about specific staged changes. A set with
        // nothing staged has nothing to attest to, and recording an approval
        // against it puts a signature in the audit trail for a decision nobody
        // could have reviewed. Observed live: a change set whose staging failed
        // was still approvable, and only apply refused it.
        if change_set.mutations.is_empty() {
            return tool_error("change set has nothing staged; there is nothing to approve");
        }

        // Refuse if the approver is the creator (two-person control)
        if change_set.creator == approver && change_set.approval_waiver.is_none() {
            return tool_error(
                "two-person control: the creating token cannot approve its own change set",
            );
        }

        // Mark as approved, with the moment it happened.
        change_set.approver = Some(approver);
        change_set.approved_at = Some(unix_seconds_now());

        if let Err(e) = self.changeset_store.insert(change_set.clone()) {
            return tool_error(format!("failed to update change set: {e}"));
        }

        let result = serde_json::json!({
            "change_set_id": change_set.id,
            "approved_by": change_set.approver,
            "approval_waiver": change_set.approval_waiver,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "unifi_apply_change_set",
        description = "Applies the staged changes as a sequence of independent REST calls"
    )]
    async fn unifi_apply_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApplyChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_apply_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        // Retrieve the change set
        let mut change_set = match self.change_set_for(&args.change_set_id, &args.controller) {
            Ok(set) => set,
            Err(result) => return *result,
        };

        // Check approval
        // A change set that already ran is not a template. Re-applying one
        // whose mutations include creates issues them again -- `preimage_matches`
        // skips creates, so nothing downstream would catch the duplicate.
        if let Some(ref outcome) = change_set.outcome {
            return tool_error(format!(
                "change set has already been applied (state: {:?}); \
                 create a new change set rather than re-applying this one",
                outcome.state
            ));
        }

        if change_set.approver.is_none() && change_set.approval_waiver.is_none() {
            return tool_error("change set has not been approved");
        }

        // An approval is a statement about a controller state at a moment.
        // Without this the packaged deployment advertised a 300-second window
        // via --approval-timeout-secs and honoured no window at all: a
        // persisted approval stayed usable for as long as the state file did.
        if change_set.approval_waiver.is_none() {
            let approved_at = change_set.approved_at.unwrap_or(0);
            let age = unix_seconds_now().saturating_sub(approved_at);
            if age > self.approval_timeout_secs {
                return tool_error(format!(
                    "approval expired {}s ago (timeout {}s); re-approve before applying",
                    age - self.approval_timeout_secs,
                    self.approval_timeout_secs
                ));
            }
        }

        let preimage = match &change_set.preimage {
            Some(p) => p,
            None => return tool_error("change set has no pre-image"),
        };

        // Get the client
        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // Apply the change set
        let outcome = apply_sequentially(&client, preimage, &change_set.mutations).await;

        // Store the outcome
        change_set.outcome = Some(outcome.clone());
        if let Err(e) = self.changeset_store.insert(change_set.clone()) {
            return tool_error(format!("failed to update change set: {e}"));
        }

        // Build result
        let state_str = match outcome.state {
            State::Applied => "applied",
            State::AppliedUnverified => "applied_unverified",
            State::Partial => "partial",
            State::PartialRollbackFailed => "partial_rollback_failed",
            State::RefusedStale => "refused_stale",
        };

        let result = serde_json::json!({
            "change_set_id": change_set.id,
            "state": state_str,
            "succeeded": outcome.succeeded.len(),
            "failed": outcome.failed.len(),
            "attempted_and_failed": outcome.attempted_and_failed.len(),
            "never_attempted": outcome.never_attempted.len(),
            "rollback_failures": outcome.rollback_failures,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "unifi_get_change_set",
        description = "Returns the current status and contents of a change set"
    )]
    async fn unifi_get_change_set(
        &self,
        Parameters(args): Parameters<changeset::GetChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_get_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        // Retrieve the change set
        let change_set = match self.change_set_for(&args.change_set_id, &args.controller) {
            Ok(set) => set,
            Err(result) => return *result,
        };

        let state_str = if let Some(ref outcome) = change_set.outcome {
            match outcome.state {
                State::Applied => "applied",
                State::AppliedUnverified => "applied_unverified",
                State::Partial => "partial",
                State::PartialRollbackFailed => "partial_rollback_failed",
                State::RefusedStale => "refused_stale",
            }
        } else if change_set.approver.is_some() || change_set.approval_waiver.is_some() {
            "approved"
        } else {
            "pending"
        };

        let result = serde_json::json!({
            "change_set_id": change_set.id,
            "controller": change_set.controller,
            "description": change_set.description,
            "creator": change_set.creator,
            "approver": change_set.approver,
            "approval_waiver": change_set.approval_waiver,
            "state": state_str,
            "mutation_count": change_set.mutations.len(),
            "outcome": change_set.outcome.as_ref().map(|o| serde_json::json!({
                "state": state_str,
                "succeeded": o.succeeded.len(),
                "failed": o.failed.len(),
                "attempted_and_failed": o.attempted_and_failed.len(),
                "never_attempted": o.never_attempted.len(),
                "rollback_failures": o.rollback_failures,
            })),
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }
}

/// Apply cache hints to a tool list when the client negotiated 2026-07-28 or later.
fn listed_tools(tools: Vec<rmcp::model::Tool>, add_cache_hints: bool) -> ListToolsResult {
    let listed = ListToolsResult::with_all_items(tools);
    if add_cache_hints {
        listed
            .with_ttl_ms(300_000)
            .with_cache_scope(rmcp::model::CacheScope::Private)
    } else {
        listed
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for UnifiServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rustunifimcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "UniFi Network MCP server. Controller-addressed tools take (controller, ...); \
                 the server routes to the controller by name.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&context.extensions);
        let all_tools = self.tool_router.list_all();
        let visible = filter_tools_for_scope(all_tools, caller, WRITE_TOOLS);
        // `with_all_items` leaves `ttl_ms` and `cache_scope` unset, and both
        // are omitted on the wire. A 2026-07-28 client validates the tools/list
        // result and rejects one without them — reported as "tools fetch
        // failed" against a server that is otherwise healthy and fast. Servers
        // that do not override `list_tools` get these from rmcp's generated
        // handler; this one filters by scope, so it supplies them itself.
        //
        // `private`: the list is per token, so a cache keyed only on the URL
        // must not serve one caller's surface to another.
        let cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        Ok(listed_tools(visible, cache_hints))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn write_tools_is_not_empty() {
        assert!(
            !WRITE_TOOLS.is_empty(),
            "WRITE_TOOLS must never be empty — an empty registry lets wildcards reach writes"
        );
    }

    /// The router and the registry must agree, in both directions.
    ///
    /// A name in `TOOL_NAMES` the server does not serve is a promise it cannot
    /// keep — `unifi_add_controller` was exactly that, so its documented
    /// "edit the file and HUP" guidance could never reach a caller. A tool the
    /// server serves that is absent from `TOOL_NAMES` is worse: it escapes the
    /// `WRITE_TOOLS` classification entirely, which is how a mutating tool
    /// becomes reachable by a wildcard token.
    #[test]
    fn the_router_serves_exactly_the_registered_tools() {
        use rustunifimcp_core::tools::TOOL_NAMES;
        use std::collections::BTreeSet;

        let router = UnifiServer::unifi_tool_router();
        let all_tools = router.list_all();
        let served_names: BTreeSet<String> =
            all_tools.iter().map(|tool| tool.name.to_string()).collect();
        let registered_names: BTreeSet<String> =
            TOOL_NAMES.iter().map(|s| (*s).to_owned()).collect();

        // Check for tools in TOOL_NAMES but not served.
        let missing_from_router: Vec<String> = registered_names
            .difference(&served_names)
            .cloned()
            .collect();
        assert!(
            missing_from_router.is_empty(),
            "TOOL_NAMES declares tools the server does not serve: {:?}",
            missing_from_router
        );

        // Check for tools served but not in TOOL_NAMES.
        let missing_from_registry: Vec<String> = served_names
            .difference(&registered_names)
            .cloned()
            .collect();
        assert!(
            missing_from_registry.is_empty(),
            "Server serves tools absent from TOOL_NAMES: {:?}",
            missing_from_registry
        );

        // Both directions pass — the sets are equal.
    }

    #[tokio::test]
    async fn change_set_survives_state_file_round_trip() {
        use tempfile::NamedTempFile;

        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();

        let set = ChangeSet {
            approved_at: None,
            id: "test-round-trip".to_owned(),
            controller: "home".to_owned(),
            description: "test".to_owned(),
            creator: "alice".to_owned(),
            approver: None,
            approval_waiver: None,
            preimage: None,
            mutations: Vec::new(),
            outcome: None,
        };

        {
            let store = ChangeSetStore::new(Some(path.clone())).unwrap();
            store.insert(set.clone()).unwrap();
        }

        // Reload from file
        let store2 = ChangeSetStore::new(Some(path)).unwrap();
        let retrieved = store2.get("test-round-trip").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "test-round-trip");
    }

    #[tokio::test]
    async fn lab_mode_records_both_waiver_fields() {
        use tempfile::NamedTempFile;

        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();
        let store = ChangeSetStore::new(Some(path)).unwrap();

        let set = ChangeSet {
            approved_at: None,
            id: "test-waiver".to_owned(),
            controller: "home".to_owned(),
            description: "test".to_owned(),
            creator: "alice".to_owned(),
            approver: None,
            approval_waiver: Some("lab-mode".to_owned()),
            preimage: None,
            mutations: Vec::new(),
            outcome: None,
        };

        store.insert(set.clone()).unwrap();

        let retrieved = store.get("test-waiver").unwrap().unwrap();
        assert_eq!(retrieved.approver, None);
        assert_eq!(retrieved.approval_waiver, Some("lab-mode".to_owned()));
    }

    /// Guards against a handler being reduced to a stub again.
    ///
    /// Phase 6 shipped the seven change-set tools as honest refusals before
    /// they were wired to the machinery. That was the correct interim state,
    /// but it must not silently return: a stubbed handler advertises a tool
    /// that cannot do its job. This asserts the refusal literal is absent
    /// from the handler code, so re-stubbing one fails the test run.
    #[test]
    fn no_change_set_handler_is_a_stub() {
        let source = include_str!("mod.rs");
        let handlers = source
            .split("#[cfg(test)]")
            .next()
            .expect("source has a non-test prefix");
        // Assembled at runtime so this assertion cannot match itself.
        let needle = ["not", "yet", "implemented"].join(" ");
        assert!(
            !handlers.contains(&needle),
            "a change-set handler still returns the {needle:?} refusal; \
             Phase 6 requires all seven wired to the change-set machinery"
        );
        for tool in WRITE_TOOLS {
            assert!(
                source.contains(tool),
                "write tool {tool} has no handler in this module"
            );
        }
    }
}
