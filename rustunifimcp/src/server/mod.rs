//! The MCP server handler.

use mecmcp_auth::NoGrant;
use mecmcp_changeset::{
    ApplyHandle, ChangeSetRecord, ChangeSetState, ChangesetCoordinator, PreviewRecord,
    change_set_digest, preview_digest,
};
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
        Preimage, StagedMutation, State, UnifiTransaction, ZoneIndex, actions_for,
        apply_sequentially, check_zone_deletions, check_zone_references, diff_against_preimage,
        fingerprint_of, mutations_of, preimage_of, referenced_zone_ids, validate_locally,
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
    /// The change-set lifecycle.
    ///
    /// `mecmcp-changeset`'s coordinator, not a map: it owns the transition
    /// policy, the claim-before-apply and the preview-bound approval, and the
    /// approval TTL that `--approval-timeout-secs` configures.
    coordinator: Arc<ChangesetCoordinator>,
    /// Change sets created but not yet staged into.
    ///
    /// The coordinator cannot hold one. Its persistence layer refuses to load
    /// a state file containing a change set with no actions, so persisting an
    /// empty plan makes the *whole* store unloadable at the next start -- a
    /// fault that CI cannot see, because nothing in a test run restarts. And
    /// an empty change set has nothing to protect: no plan, no pre-image, no
    /// approval. So it is held here until the first mutation is staged, and a
    /// restart loses exactly nothing.
    drafts: Arc<std::sync::RwLock<BTreeMap<String, Draft>>>,
    /// SSDF evidence, when the pipeline is configured.
    ///
    /// The coordinator emits the approval records itself. The proposal and the
    /// two apply records belong to paths this server drives, so it needs the
    /// recorder too.
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    /// Tool router.
    tool_router: ToolRouter<Self>,
}

/// A change set that exists but has nothing staged into it.
#[derive(Debug, Clone)]
pub struct Draft {
    /// The controller it was created against.
    controller: String,
    /// The principal who created it.
    owner: String,
    /// What it is for, which becomes the preview's description.
    description: String,
    /// When it was created, so a forgotten draft does not live forever.
    created_at_unix: u64,
}

/// How many unstaged change sets may be held at once.
///
/// Bounded because a draft is reachable without touching a controller, so an
/// unbounded map is a way to grow the process with no write ever happening.
const MAX_DRAFTS: usize = 32;

impl UnifiServer {
    /// Create a new server with the given registry, lab mode, and coordinator.
    ///
    /// # Errors
    ///
    /// Returns an error if any client cannot be built.
    pub fn new(
        registry: Arc<ControllerRegistry>,
        lab_mode: bool,
        coordinator: Arc<ChangesetCoordinator>,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    ) -> Result<Self, UnifiError> {
        let clients = Self::build_clients(&registry)?;
        Ok(Self {
            registry,
            clients: Arc::new(std::sync::RwLock::new(clients)),
            lab_mode,
            coordinator,
            drafts: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
            evidence,
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

    /// The principal behind this call.
    fn principal(caller: Option<&mecmcp_auth::CallerCtx<NoGrant>>) -> String {
        caller.map_or_else(|| "unknown".to_owned(), |ctx| ctx.token_name.clone())
    }

    /// Fetch a change set, refusing a controller that does not own it.
    ///
    /// The coordinator addresses a change set by `(id, device)` and refuses a
    /// mismatch itself, which closes a hole the map-backed store had: every
    /// change-set tool takes a `controller` argument and used it to pick the
    /// client without ever comparing it to the controller the set was planned
    /// against, so a set could be validated -- and applied -- against another.
    async fn record_for(
        &self,
        change_set_id: &str,
        controller: &str,
    ) -> Result<ChangeSetRecord, Box<CallToolResult>> {
        self.coordinator
            .change_set(change_set_id, controller)
            .await
            .map_err(|error| {
                Box::new(tool_error(format!(
                    "change set {change_set_id} on {controller} ({}): {}",
                    error.field(),
                    error.message()
                )))
            })
    }

    /// Read the plan back off a stored record.
    fn plan_of(
        record: &ChangeSetRecord,
    ) -> Result<(Vec<StagedMutation>, Preimage), Box<CallToolResult>> {
        let mutations = mutations_of(&record.actions)
            .map_err(|error| Box::new(tool_error(format!("stored change set: {error}"))))?;
        let preimage = preimage_of(&record.actions)
            .map_err(|error| Box::new(tool_error(format!("stored change set: {error}"))))?;
        Ok((mutations, preimage))
    }

    /// Render the preview an approver signs off on.
    ///
    /// Stored as JSON rather than prose because it is read by a model relaying
    /// to an operator, and because it is also where the description lives:
    /// `ChangeSetRecord` has no field for one, and a side-car map holding it
    /// would be a second store to disagree with the first.
    ///
    /// The atomicity declaration is part of the preview deliberately. UniFi
    /// offers no atomic apply, no dry run and no guaranteed rollback, and an
    /// approver who is not told that is approving something else.
    fn render_preview(
        controller: &str,
        description: &str,
        mutations: &[StagedMutation],
        preimage: &Preimage,
    ) -> Result<String, Box<CallToolResult>> {
        let diff = diff_against_preimage(preimage, mutations)
            .map_err(|error| Box::new(tool_error(format!("failed to compute diff: {error}"))))?;
        let atomicity = UnifiTransaction::atomicity();

        serde_json::to_string_pretty(&serde_json::json!({
            "controller": controller,
            "description": description,
            "staged_count": mutations.len(),
            "atomicity": {
                "atomic_apply": atomicity.atomic_apply,
                "dry_run_validation": atomicity.dry_run_validation,
                "guaranteed_rollback": atomicity.guaranteed_rollback,
                "note": "UniFi writes directly to running state: a partial apply is \
                         reachable and rollback is best-effort",
            },
            "changes": diff.changes,
        }))
        .map_err(|error| Box::new(tool_error(format!("failed to render the preview: {error}"))))
    }

    /// The description carried in a record's preview.
    fn description_of(record: &ChangeSetRecord) -> Result<String, Box<CallToolResult>> {
        let Some(preview) = record.preview.as_ref() else {
            return Err(Box::new(tool_error(
                "change set has no stored preview; create it again",
            )));
        };
        let parsed: serde_json::Value = serde_json::from_str(&preview.artifact).map_err(|_| {
            Box::new(tool_error(
                "stored change set: the preview is not the shape this server writes",
            ))
        })?;
        Ok(parsed
            .get("description")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned())
    }

    /// Record a change set that has nothing staged yet.
    ///
    /// Mirrors the coordinator's own rule -- one pending change set per
    /// principal per controller -- so a draft cannot be used to sidestep it,
    /// and sweeps drafts older than the approval window on the way in.
    fn hold_draft(&self, id: String, draft: Draft) -> Result<(), Box<CallToolResult>> {
        let deadline = self.coordinator.approval_ttl().as_secs();
        let now = unix_seconds_now();

        let mut drafts = self
            .drafts
            .write()
            .map_err(|_| Box::new(tool_error("drafts lock poisoned".to_owned())))?;

        drafts.retain(|_, held| now.saturating_sub(held.created_at_unix) <= deadline);

        if let Some((existing, _)) = drafts
            .iter()
            .find(|(_, held)| held.owner == draft.owner && held.controller == draft.controller)
        {
            return Err(Box::new(tool_error(format!(
                "change set {existing} on '{}' has nothing staged yet; stage into it or \
                 let it lapse before creating another",
                draft.controller
            ))));
        }

        if drafts.len() >= MAX_DRAFTS {
            return Err(Box::new(tool_error(format!(
                "{MAX_DRAFTS} change sets are open with nothing staged; stage into one or \
                 let them lapse"
            ))));
        }

        drafts.insert(id, draft);
        Ok(())
    }

    /// The draft for this id, if it is one and the caller named its controller.
    fn draft(&self, change_set_id: &str, controller: &str) -> Option<Draft> {
        self.drafts
            .read()
            .ok()?
            .get(change_set_id)
            .filter(|draft| draft.controller == controller)
            .cloned()
    }

    /// Forget a draft that has become a real change set.
    fn release_draft(&self, change_set_id: &str) {
        if let Ok(mut drafts) = self.drafts.write() {
            drafts.remove(change_set_id);
        }
    }

    /// Refuse a plan the state file could not be reloaded with.
    ///
    /// Neither `insert_change_set` nor `update_change_set` checks the
    /// configured ceilings against a record's actions -- only
    /// `create_change_set` does, and this server cannot use it because a change
    /// set is created before anything is staged into it. Without this a caller
    /// can stage past the limits, have the record persist, and find the server
    /// refusing to start afterwards because the load path enforces a structural
    /// cap the write path did not.
    fn check_plan_limits(record: &ChangeSetRecord) -> Result<(), Box<CallToolResult>> {
        let limits = crate::changeset_state::limits();

        mecmcp_changeset::validate_change_set_actions(&record.actions, &limits).map_err(
            |error| {
                Box::new(tool_error(format!(
                    "staged plan refused ({}): {}",
                    error.field(),
                    error.message()
                )))
            },
        )?;

        if let Some(preview) = record.preview.as_ref()
            && preview.artifact.len() > limits.max_preview_bytes
        {
            return Err(Box::new(tool_error(format!(
                "the preview for this change set is {} bytes, over the {} the store \
                 accepts; stage fewer changes at once",
                preview.artifact.len(),
                limits.max_preview_bytes
            ))));
        }

        Ok(())
    }

    /// Rewrite a record's plan, its fingerprint, its digest and its preview.
    ///
    /// All four move together. The digest binds `(owner, device, fingerprint,
    /// actions)` and the approval binds the digest, so a plan changed without
    /// its digest would carry an approval for a plan nobody approved.
    fn with_plan(
        mut record: ChangeSetRecord,
        mutations: &[StagedMutation],
        preimage: &Preimage,
        description: &str,
    ) -> Result<ChangeSetRecord, Box<CallToolResult>> {
        let actions = actions_for(mutations, preimage);
        let fingerprint = fingerprint_of(&actions)
            .map_err(|error| Box::new(tool_error(format!("failed to fingerprint: {error}"))))?;
        let artifact = Self::render_preview(&record.device, description, mutations, preimage)?;

        record.actions = actions
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| Box::new(tool_error(format!("failed to store the plan: {error}"))))?;
        record.expected_candidate_fingerprint = fingerprint;
        record.digest = change_set_digest(
            &record.owner,
            &record.device,
            &record.expected_candidate_fingerprint,
            &record.actions,
        )
        .map_err(|error| Box::new(tool_error(format!("failed to digest the plan: {error}"))))?;
        record.preview = Some(PreviewRecord {
            digest: preview_digest(&artifact),
            artifact,
            job_id: None,
        });

        Ok(record)
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

        let owner = Self::principal(caller.as_ref());

        // The controller has to be one this server knows before a change set
        // names it: the coordinator addresses records by device, and a record
        // naming a controller absent from the inventory can never be applied.
        if let Err(result) = self.client_for(&args.controller) {
            return *result;
        }

        // Held as a draft, not written to the store. The coordinator's
        // persistence layer refuses to load a state file containing a change
        // set with no actions, so writing an empty plan here would make the
        // whole store unloadable at the next restart -- and nothing in a test
        // run restarts, so CI would never see it. The record is created on the
        // first stage, which is also when there is a plan to propose.
        let id = crate::changeset_state::new_change_set_id();
        let draft = Draft {
            controller: args.controller.clone(),
            owner,
            description: args.description,
            created_at_unix: unix_seconds_now(),
        };

        if let Err(result) = self.hold_draft(id.clone(), draft) {
            return *result;
        }

        let result = serde_json::json!({
            "change_set_id": id,
            "controller": args.controller,
            "state": "draft",
            "note": "nothing is staged yet; a draft is held in memory and is lost on \
                     restart. It becomes a change set on the first unifi_stage_change.",
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

        // A draft on its first stage, or a change set already in the store.
        let draft = self.draft(&args.change_set_id, &args.controller);
        let existing = match draft {
            Some(_) => None,
            None => match self.record_for(&args.change_set_id, &args.controller).await {
                Ok(record) => Some(record),
                Err(result) => return *result,
            },
        };

        // Staging rewrites the plan, and with it the digest an approval binds
        // to. Allowing it after approval would let a reviewed plan be swapped
        // for an unreviewed one while the approval stayed attached, which is
        // the whole reason the digest exists.
        if let Some(ref record) = existing
            && record.state != ChangeSetState::Planned
        {
            return tool_error(format!(
                "change set is {} and can no longer be staged into; create a new one",
                record.state.as_str()
            ));
        }

        let (description, owner) = match (&draft, &existing) {
            (Some(draft), _) => (draft.description.clone(), draft.owner.clone()),
            (None, Some(record)) => match Self::description_of(record) {
                Ok(description) => (description, record.owner.clone()),
                Err(result) => return *result,
            },
            (None, None) => unreachable!("one of the two is always present"),
        };

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let mut mutations = match &existing {
            Some(record) => match Self::plan_of(record) {
                Ok(plan) => plan.0,
                Err(result) => return *result,
            },
            None => Vec::new(),
        };

        for spec in args.mutations {
            mutations.push(match spec {
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
            });
        }

        // Re-captured over the whole plan, not only the new mutations: the
        // fingerprint stands in for a candidate UniFi does not have, so it has
        // to describe the state the plan as a whole was built against.
        let preimage = match Preimage::capture_preimage(&client, &mutations).await {
            Ok(preimage) => preimage,
            Err(e) => return tool_error(format!("failed to capture pre-image: {e}")),
        };

        let staged_count = mutations.len();
        let base = existing.unwrap_or_else(|| ChangeSetRecord {
            id: args.change_set_id.clone(),
            owner,
            device: args.controller.clone(),
            expected_candidate_fingerprint: String::new(),
            actions: Vec::new(),
            digest: String::new(),
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: unix_seconds_now()
                .saturating_add(self.coordinator.approval_ttl().as_secs()),
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: None,
            task_id: None,
            apply_without_handle: false,
        });

        let staged = match Self::with_plan(base, &mutations, &preimage, &description) {
            Ok(record) => record,
            Err(result) => return *result,
        };

        if let Err(result) = Self::check_plan_limits(&staged) {
            return *result;
        }

        if draft.is_some() {
            // The plan exists now, so the change set does too -- and so does
            // something to propose. `insert_change_set` is what enforces one
            // pending set per principal per controller.
            let (digest, device, owner) = (
                staged.digest.clone(),
                staged.device.clone(),
                staged.owner.clone(),
            );
            if let Err(error) = self.coordinator.insert_change_set(staged).await {
                return tool_error(format!(
                    "failed to store change set ({}): {}",
                    error.field(),
                    error.message()
                ));
            }
            self.release_draft(&args.change_set_id);

            // The coordinator emits this itself from `create_change_set`, which
            // this server cannot use: that call requires the actions up front,
            // and a change set here is created before anything is staged.
            if let Some(recorder) = self.evidence.as_ref() {
                recorder.proposal(
                    &args.change_set_id,
                    &args.change_set_id,
                    &device,
                    &owner,
                    &digest,
                );
            }
        } else if let Err(error) = self
            // Conditional on the state still being `Planned`. An unconditional
            // write would let a concurrent approval be overwritten by a staging
            // call that read the record before it.
            .coordinator
            .update_change_set_from(ChangeSetState::Planned, staged)
            .await
        {
            return tool_error(format!(
                "failed to update change set ({}): {}",
                error.field(),
                error.message()
            ));
        }

        let result = serde_json::json!({
            "change_set_id": args.change_set_id,
            "staged_count": staged_count,
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

        let record = match self.record_for(&args.change_set_id, &args.controller).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let (mutations, preimage) = match Self::plan_of(&record) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };

        let diff = match diff_against_preimage(&preimage, &mutations) {
            Ok(diff) => diff,
            Err(e) => return tool_error(format!("failed to compute diff: {e}")),
        };

        let result = serde_json::json!({
            "change_set_id": record.id,
            "computed": diff.computed,
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

        let record = match self.record_for(&args.change_set_id, &args.controller).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let (mutations, preimage) = match Self::plan_of(&record) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };

        if let Err(e) = validate_locally(&preimage, &mutations) {
            return tool_error(format!("local validation failed: {e}"));
        }

        // A zone this set deletes must not be left referenced by anything else
        // in the set. Checked first because it needs no controller round trip:
        // it compares the set against itself and against the pre-image.
        if let Err(e) = check_zone_deletions(&preimage, &mutations) {
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
        if !referenced_zone_ids(&mutations).is_empty() {
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
                        "could not read the firewall zone list from controller '{}', so zone                          references cannot be checked: {e}",
                        args.controller
                    ));
                }
            };

            let zones = match ZoneIndex::from_zone_list(&raw) {
                Ok(zones) => zones,
                Err(e) => {
                    return tool_error(format!(
                        "could not read the firewall zone list from controller '{}', so zone                          references cannot be checked: {e}",
                        args.controller
                    ));
                }
            };

            if let Err(e) = check_zone_references(&zones, &mutations) {
                return tool_error(format!("reference check failed: {e}"));
            }
        }

        let result = serde_json::json!({
            "change_set_id": record.id,
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
        description = "Approves a change set for apply. Two-person control: the creating \
                       token cannot approve its own set unless lab mode waives it, and a \
                       waiver is recorded as a waiver rather than as an approval. Pass \
                       expected_digest to bind the approval to the plan you read."
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

        let approver = Self::principal(caller.as_ref());

        let record = match self.record_for(&args.change_set_id, &args.controller).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        // An approval is a statement about specific staged changes. A set with
        // nothing staged has nothing to attest to, and recording an approval
        // against it puts a signature in the audit trail for a decision nobody
        // could have reviewed. Observed live: a change set whose staging failed
        // was still approvable, and only apply refused it.
        if record.actions.is_empty() {
            return tool_error("change set has nothing staged; there is nothing to approve");
        }

        // And it must be a statement about something the approver could read.
        // The preview is written at create and rewritten at every stage, so an
        // absent one means a record this server did not write.
        let Some(preview) = record.preview.clone() else {
            return tool_error(
                "approval refused: this change set has no stored preview, so there is \
                 nothing to review. Create it again.",
            );
        };

        // An approver who names the digest they read is bound to that plan. Not
        // naming one falls back to the stored digest, which makes the
        // lifecycle's digest check a tautology -- it compares the stored value
        // with itself -- so the argument is the only way an approval can
        // actually attest to a specific plan rather than to whatever the record
        // holds when the call lands.
        if let Some(ref expected) = args.expected_digest
            && expected != &record.digest
        {
            return tool_error(format!(
                "approval refused: the plan has changed since you read it. You named \
                 digest {expected}; the change set now holds {}. Read it again before \
                 approving.",
                record.digest
            ));
        }

        // Two-person control when a second principal is present; the lab-mode
        // waiver only when the owner is approving their own set. The waiver is
        // a distinct call, not a flag on the approval, so the record says which
        // of the two happened -- `approver: None` cannot tell "nobody has
        // approved this" from "this was approved without review".
        let outcome = if approver == record.owner {
            if !self.lab_mode {
                return tool_error(
                    "two-person control: the creating token cannot approve its own change set",
                );
            }
            self.coordinator
                .waive_approval(
                    args.change_set_id.clone(),
                    args.controller.clone(),
                    approver.clone(),
                    record.digest.clone(),
                )
                .await
        } else {
            self.coordinator
                .approve_change_set(
                    args.change_set_id.clone(),
                    args.controller.clone(),
                    approver.clone(),
                    record.digest.clone(),
                )
                .await
        };

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                return tool_error(format!(
                    "approval refused ({}): {}",
                    error.field(),
                    error.message()
                ));
            }
        };

        let result = serde_json::json!({
            "change_set_id": outcome.change_set_id,
            "state": outcome.state.as_str(),
            "approved_by": outcome.approver,
            "approval_waiver": outcome.approval_waiver,
            "expires_at_unix": outcome.expires_at_unix,
            "approved_digest": outcome.digest,
            "preview": preview.artifact,
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

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // Claim first, and only then read the plan. The claim is the single
        // legal route from `Approved` to `Applying`, and it does the check and
        // the write under one lock -- so two concurrent applies cannot both
        // observe `Approved` and both proceed, which the map-backed store
        // allowed. It is also what enforces the approval window and refuses a
        // set that has already run: an approval reaches `Applying` once and
        // there is no route back.
        //
        // `ApplyHandle::None` because UniFi returns no task handle to re-probe.
        // A crash mid-apply therefore leaves the record `Applying` rather than
        // being read as `Failed` at the next start: the writes are not
        // idempotent, a partial apply is a reachable outcome, and only the
        // controller knows which of them landed. Detectable, not recoverable,
        // and a human has to look -- which is the honest state, and keeps the
        // approval from being spent twice.
        // The deadline is checked here because the claim does not check it. It
        // refuses anything that is not `Approved`, and approve refuses an
        // expired set -- but a set approved inside the window and applied long
        // after it still claims cleanly, which is exactly the case
        // `--approval-timeout-secs` exists to stop. `change_set_status` is the
        // path that transitions and persists `Approved -> Expired`, so the
        // record is left Expired rather than merely reported as stale.
        match self
            .coordinator
            .change_set_status(args.change_set_id.clone(), args.controller.clone())
            .await
        {
            Ok(status) if status.state == ChangeSetState::Expired => {
                return tool_error(format!(
                    "apply refused: the approval window closed at {}; re-plan and \
                     re-approve before applying",
                    status.expires_at_unix
                ));
            }
            Ok(_) => {}
            Err(error) => {
                return tool_error(format!(
                    "apply refused ({}): {}",
                    error.field(),
                    error.message()
                ));
            }
        }

        let claimed = match self
            .coordinator
            .claim_change_set_for_apply(&args.change_set_id, &args.controller, ApplyHandle::None)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                return tool_error(format!(
                    "apply refused ({}): {}",
                    error.field(),
                    error.message()
                ));
            }
        };

        // A claim has no route back to `Approved`, so a failure between here
        // and the first write has to settle the record itself or it sits in
        // `Applying` for good, with its approval neither spent nor spendable.
        // Nothing has been written at this point, so `Failed` is accurate.
        let (mutations, preimage) = match Self::plan_of(&claimed) {
            Ok(plan) => plan,
            Err(result) => {
                let mut abandoned = claimed;
                abandoned.state = ChangeSetState::Failed;
                if let Err(error) = self.coordinator.update_change_set(abandoned).await {
                    tracing::error!(
                        change_set_id = %args.change_set_id,
                        field = error.field(),
                        message = error.message(),
                        "a claimed change set could not be settled after its plan \
                         failed to read; it will stay Applying"
                    );
                }
                return *result;
            }
        };

        let principal = Self::principal(caller.as_ref());

        // Recorded before the controller is touched, and the apply is refused
        // if it cannot be made durable. An intent that survives only in memory
        // proves nothing about a crash, and the point of the record is to
        // establish that this write was going to happen before it did.
        if let Some(recorder) = self.evidence.as_ref()
            && let Err(error) = recorder.apply_intent(
                &args.change_set_id,
                &args.change_set_id,
                &args.controller,
                &principal,
            )
        {
            let mut abandoned = claimed;
            abandoned.state = ChangeSetState::Failed;
            let _ = self.coordinator.update_change_set(abandoned).await;
            return tool_error(format!(
                "apply refused: the SSDF apply-intent record could not be made durable, \
                 so the write was not attempted: {error}"
            ));
        }

        let outcome = apply_sequentially(&client, &preimage, &mutations).await;

        let state_str = match outcome.state {
            State::Applied => "applied",
            State::AppliedUnverified => "applied_unverified",
            State::Partial => "partial",
            State::PartialRollbackFailed => "partial_rollback_failed",
            State::RefusedStale => "refused_stale",
        };

        // The breakdown goes to the audit trail, which is where an event
        // belongs -- the state file holds state. It has no home on
        // `ChangeSetRecord`, which is `deny_unknown_fields`, and the shared
        // crate's `OperationRecord` was the wrong container: its non-terminal
        // states make every later operation on the device refuse as
        // unreconciled, which is right for a vendor whose commit either lands
        // or does not, and would wedge this one -- a partial apply here is a
        // routine outcome and there is no tool to clear it.
        //
        // Emitted before the state write, so the record of what happened
        // survives even if recording the verdict fails.
        tracing::info!(
            target: "audit",
            event = "unifi_change_set_applied",
            change_set_id = %args.change_set_id,
            controller = %args.controller,
            principal = %principal,
            outcome = state_str,
            succeeded = outcome.succeeded.len(),
            failed = outcome.failed.len(),
            attempted_and_failed = outcome.attempted_and_failed.len(),
            never_attempted = outcome.never_attempted.len(),
            rollback_failures = outcome.rollback_failures.len(),
            "change set applied"
        );

        // `Applied` when every write landed, and for an apply that landed but
        // could not be re-read to confirm it: it did apply, and calling that
        // `Failed` asserts an outcome nobody observed. The distinction between
        // the two lives in the audit record above and in the result below.
        // Everything else is `Failed`, a partial included -- a record claiming
        // a change landed when only some of it did is worse than one an
        // operator has to go and read.
        let mut settled = claimed;
        settled.state = if matches!(outcome.state, State::Applied | State::AppliedUnverified) {
            ChangeSetState::Applied
        } else {
            ChangeSetState::Failed
        };

        // The device has acted, so this cannot fail closed -- refusing now
        // would not un-act it. Reported instead.
        if let Some(recorder) = self.evidence.as_ref()
            && let Err(error) = recorder.result_receipt(
                &args.change_set_id,
                &args.change_set_id,
                &args.controller,
                &principal,
                matches!(outcome.state, State::Applied | State::AppliedUnverified),
                state_str,
            )
        {
            tracing::error!(
                change_set_id = %args.change_set_id,
                %error,
                "the SSDF result receipt could not be made durable"
            );
        }

        if let Err(error) = self.coordinator.update_change_set(settled).await {
            // The writes have already happened, so this is reported rather than
            // returned as the outcome: the caller needs the apply result, and
            // an unrecorded outcome is a separate fault.
            tracing::error!(
                change_set_id = %args.change_set_id,
                field = error.field(),
                message = error.message(),
                "the apply outcome could not be recorded"
            );
        }

        let result = serde_json::json!({
            "change_set_id": args.change_set_id,
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

        // A draft has no record yet, and reporting "not found" for a change set
        // this server just handed out an id for would read as a fault.
        if let Some(draft) = self.draft(&args.change_set_id, &args.controller) {
            return tool_result(
                Ok::<_, String>(serde_json::json!({
                    "change_set_id": args.change_set_id,
                    "controller": draft.controller,
                    "description": draft.description,
                    "creator": draft.owner,
                    "state": "draft",
                    "mutation_count": 0,
                    "note": "nothing is staged yet; this draft is held in memory and is \
                             lost on restart",
                })),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }

        // Through `change_set_status`, because it is the path that transitions
        // and persists a set whose deadline has passed. Reading the record raw
        // reports `planned` beside an `expires_at_unix` already in the past.
        if let Err(error) = self
            .coordinator
            .change_set_status(args.change_set_id.clone(), args.controller.clone())
            .await
        {
            return tool_error(format!(
                "change set {} on {} ({}): {}",
                args.change_set_id,
                args.controller,
                error.field(),
                error.message()
            ));
        }

        let record = match self.record_for(&args.change_set_id, &args.controller).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let description = Self::description_of(&record).unwrap_or_default();

        // The state is the lifecycle's, not a string derived from which fields
        // happen to be populated. `approved` and `pending` used to be inferred
        // from whether an approver was set, which cannot distinguish an expired
        // approval or a cancelled set from a pending one.
        let result = serde_json::json!({
            "change_set_id": record.id,
            "controller": record.device,
            "description": description,
            "creator": record.owner,
            "approver": record.approval.as_ref().and_then(|a| a.approver.clone()),
            "approval_waiver": record
                .approval
                .as_ref()
                .and_then(|a| a.waived.as_ref())
                .map(|waiver| waiver.kind.as_str()),
            "state": record.state.as_str(),
            "mutation_count": record.actions.len(),
            "expires_at_unix": record.expires_at_unix,
            "plan_digest": record.digest,
            "expected_preimage_fingerprint": record.expected_candidate_fingerprint,
            "preview": record.preview.as_ref().map(|preview| preview.artifact.clone()),
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
    use std::time::Duration;

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

    /// Build a `Planned` record the way `unifi_create_change_set` does.
    fn planned_record(owner: &str, controller: &str, ttl: u64) -> ChangeSetRecord {
        let record = ChangeSetRecord {
            id: crate::changeset_state::new_change_set_id(),
            owner: owner.to_owned(),
            device: controller.to_owned(),
            expected_candidate_fingerprint: String::new(),
            actions: Vec::new(),
            digest: String::new(),
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: unix_seconds_now().saturating_add(ttl),
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: None,
            task_id: None,
            apply_without_handle: false,
        };
        let staged = vec![StagedMutation::create(
            "firewall_policy",
            serde_json::json!({ "name": "probe" }),
        )];
        UnifiServer::with_plan(
            record,
            &staged,
            &Preimage::from_resources(Vec::new()),
            "test",
        )
        .map_err(|_| "with_plan refused a freshly built record")
        .expect("a freshly built record must plan")
    }

    fn coordinator_at(path: Option<&std::path::Path>) -> Arc<ChangesetCoordinator> {
        crate::changeset_state::build_coordinator(path, Duration::from_secs(300), true, None)
            .expect("coordinator")
    }

    /// An approval that does not survive a restart is not an approval, and the
    /// pre-image that went with it is what stands between a partial apply and
    /// an unrecoverable one.
    #[tokio::test]
    async fn change_set_survives_state_file_round_trip() {
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        let path = temp.path().to_path_buf();

        let id = {
            let coordinator = coordinator_at(Some(&path));
            let record = planned_record("alice", "home", 300);
            let id = record.id.clone();
            coordinator.insert_change_set(record).await.expect("insert");
            id
        };

        let reloaded = coordinator_at(Some(&path));
        let record = reloaded
            .change_set(&id, "home")
            .await
            .expect("the record must survive the restart");
        assert_eq!(record.owner, "alice");
        assert_eq!(record.state, ChangeSetState::Planned);
        assert!(
            record.preview.is_some(),
            "the preview an approver reads must survive too"
        );
        assert_eq!(
            UnifiServer::plan_of(&record)
                .map_err(|_| "plan_of")
                .expect("the plan must survive")
                .0
                .len(),
            1
        );
    }

    /// `approver: None` cannot tell "nobody has approved this" from "this was
    /// approved without review", so a waiver has to be recorded as its own
    /// fact. It is also the one thing lab mode changes about the lifecycle.
    #[tokio::test]
    async fn lab_mode_records_the_waiver_as_a_distinct_fact() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        coordinator.insert_change_set(record).await.expect("insert");

        let outcome = coordinator
            .waive_approval(id.clone(), "home".to_owned(), "alice".to_owned(), digest)
            .await
            .expect("lab mode waives the second principal");

        assert_eq!(outcome.state, ChangeSetState::Approved);
        assert_eq!(
            outcome.approval_waiver.as_deref(),
            Some("lab-mode"),
            "a waived approval must say so rather than look unapproved"
        );

        let stored = coordinator.change_set(&id, "home").await.expect("stored");
        assert!(
            stored.approval.is_some(),
            "the waiver must be recorded on the record, not only returned"
        );
    }

    /// Without lab mode the same call is a self-approval and must be refused
    /// by the lifecycle, not only by this server's own check.
    #[tokio::test]
    async fn a_waiver_is_refused_when_lab_mode_is_off() {
        let coordinator =
            crate::changeset_state::build_coordinator(None, Duration::from_secs(300), false, None)
                .expect("coordinator");
        let record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        coordinator.insert_change_set(record).await.expect("insert");

        assert!(
            coordinator
                .waive_approval(id, "home".to_owned(), "alice".to_owned(), digest)
                .await
                .is_err(),
            "a waiver outside lab mode is a self-approval"
        );
    }

    /// The claim is the only legal route to `Applying`, and an unapproved set
    /// must not reach it.
    #[tokio::test]
    async fn an_unapproved_change_set_cannot_be_claimed_for_apply() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        assert!(
            coordinator
                .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
                .await
                .is_err(),
            "a Planned change set has no approval to spend"
        );
    }

    /// And an approval is spent once. The map-backed store let two concurrent
    /// applies both observe `Approved` and both proceed.
    #[tokio::test]
    async fn an_approval_can_only_be_claimed_once() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        coordinator.insert_change_set(record).await.expect("insert");
        coordinator
            .approve_change_set(id.clone(), "home".to_owned(), "bob".to_owned(), digest)
            .await
            .expect("a second principal approves");

        coordinator
            .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
            .await
            .expect("the first claim takes the approval");
        assert!(
            coordinator
                .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
                .await
                .is_err(),
            "the second claim must find the approval spent"
        );
    }

    /// An approval is a statement about a controller state at a moment. The
    /// packaged deployment advertises a 300-second window; the lifecycle is
    /// what now honours it.
    #[tokio::test]
    async fn an_expired_approval_cannot_be_claimed() {
        let coordinator = coordinator_at(None);
        let mut record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        record.expires_at_unix = unix_seconds_now().saturating_sub(1);
        coordinator.insert_change_set(record).await.expect("insert");

        // Approval itself is refused once the window has passed, which is the
        // earlier of the two gates.
        assert!(
            coordinator
                .approve_change_set(id.clone(), "home".to_owned(), "bob".to_owned(), digest)
                .await
                .is_err(),
            "an expired change set must not be approvable"
        );
        assert!(
            coordinator
                .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
                .await
                .is_err()
        );
    }

    /// The write path does not enforce the configured ceilings -- only
    /// `create_change_set` does, and this server cannot use it -- while the
    /// load path enforces a structural cap. Staging past the limit would
    /// persist and then refuse to reload, so it is refused at stage.
    #[test]
    fn an_oversized_plan_is_refused_before_it_is_stored() {
        let limit = crate::changeset_state::limits().max_actions_per_set;
        let staged: Vec<StagedMutation> = (0..=limit)
            .map(|n| StagedMutation::create("firewall_policy", serde_json::json!({ "name": n })))
            .collect();

        let record = UnifiServer::with_plan(
            planned_record("alice", "home", 300),
            &staged,
            &Preimage::from_resources(Vec::new()),
            "too much at once",
        )
        .map_err(|_| "with_plan")
        .expect("planning is not where it is refused");

        assert!(
            UnifiServer::check_plan_limits(&record).is_err(),
            "{} actions is over the {limit} the store accepts",
            staged.len()
        );
    }

    /// And a plan inside the ceiling is not.
    #[test]
    fn a_plan_within_the_limits_is_accepted() {
        let record = planned_record("alice", "home", 300);
        assert!(UnifiServer::check_plan_limits(&record).is_ok());
    }

    /// The window runs from when the plan was written, so approving does not
    /// restart it. That is what makes `--approval-timeout-secs` bound the age
    /// of the pre-image the plan was built against, and it is a shorter window
    /// than the code this replaces enforced -- worth pinning rather than
    /// rediscovering.
    #[tokio::test]
    async fn approval_does_not_restart_the_window() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        let planned_deadline = record.expires_at_unix;
        coordinator.insert_change_set(record).await.expect("insert");

        coordinator
            .approve_change_set(id.clone(), "home".to_owned(), "bob".to_owned(), digest)
            .await
            .expect("approve");

        let approved = coordinator.change_set(&id, "home").await.expect("stored");
        assert_eq!(
            approved.expires_at_unix, planned_deadline,
            "the deadline is stamped at creation and approval must not move it"
        );
    }

    /// One pending change set per principal per controller. A second create is
    /// refused until the first reaches an outcome, which is a behaviour change
    /// from the map-backed store.
    #[tokio::test]
    async fn a_second_pending_change_set_on_one_controller_is_refused() {
        let coordinator = coordinator_at(None);
        coordinator
            .insert_change_set(planned_record("alice", "home", 300))
            .await
            .expect("the first plan is accepted");

        assert!(
            coordinator
                .insert_change_set(planned_record("alice", "home", 300))
                .await
                .is_err(),
            "one pending change set per principal per controller"
        );

        // Another controller is a different plan, and another principal is a
        // different queue.
        coordinator
            .insert_change_set(planned_record("alice", "office", 300))
            .await
            .expect("a different controller is a different plan");
        coordinator
            .insert_change_set(planned_record("bob", "home", 300))
            .await
            .expect("a different principal has their own");
    }

    /// A change set is addressed by `(id, controller)`. Naming another
    /// controller must not reach it: its resource ids mean nothing there.
    #[tokio::test]
    async fn a_change_set_is_not_reachable_from_another_controller() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        assert!(coordinator.change_set(&id, "home").await.is_ok());
        assert!(
            coordinator.change_set(&id, "office").await.is_err(),
            "a set planned against one controller must not be readable from another"
        );
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
