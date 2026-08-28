//! The MCP server handler.

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
    inventory::ControllerRegistry,
    client::UnifiClient,
    error::UnifiError,
    tools::{WRITE_TOOLS, admin, ops, read},
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

/// The UniFi MCP server.
#[derive(Clone)]
pub struct UnifiServer {
    /// Controller inventory.
    registry: Arc<ControllerRegistry>,
    /// Clients per controller.
    clients: Arc<BTreeMap<String, UnifiClient>>,
    /// Whether lab mode is enabled.
    lab_mode: bool,
    /// Tool router.
    tool_router: ToolRouter<Self>,
}

impl UnifiServer {
    /// Create a new server with the given registry and lab mode setting.
    ///
    /// # Errors
    ///
    /// Returns an error if any client cannot be built.
    pub fn new(
        registry: Arc<ControllerRegistry>,
        lab_mode: bool,
    ) -> Result<Self, UnifiError> {
        let mut clients = BTreeMap::new();
        for name in registry.names() {
            let controller = registry.get(&name)?;
            clients.insert(name.clone(), UnifiClient::new(controller)?);
        }
        Ok(Self {
            registry,
            clients: Arc::new(clients),
            lab_mode,
            tool_router: Self::unifi_tool_router(),
        })
    }

    /// Get the client for a controller.
    fn client_for(&self, controller: &str) -> Result<&UnifiClient, Box<CallToolResult>> {
        self.clients
            .get(controller)
            .ok_or_else(|| Box::new(tool_error(format!("unknown controller: {controller}"))))
    }

    /// Recover the caller from the request context.
    fn caller(context: &RequestContext<RoleServer>) -> Option<mecmcp_auth::CallerCtx<NoGrant>> {
        caller_from_extensions::<NoGrant>(&context.extensions).cloned()
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_list_resources", Some(&args.controller), WRITE_TOOLS) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::list_resources(client, &args).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_get_resource", Some(&args.controller), WRITE_TOOLS) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::get_resource(client, &args).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_query_stats", Some(&args.controller), WRITE_TOOLS) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::query_stats(client, &args).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_search", Some(&args.controller), WRITE_TOOLS) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::search(client, &args).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_list_sites", Some(&args.controller), WRITE_TOOLS) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::list_sites(client, &args).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_list_controllers", None, WRITE_TOOLS) {
            return tool_error(error);
        }

        match admin::unifi_list_controllers(&self.registry).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_add_controller", None, WRITE_TOOLS) {
            return tool_error(error);
        }

        match admin::unifi_add_controller("", "", "", None, None).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_device_action", Some(&args.controller), WRITE_TOOLS) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match ops::device_action(args, client).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_client_action", Some(&args.controller), WRITE_TOOLS) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match ops::client_action(args, client).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_backup_action",
        description = "Execute a backup action (trigger, list, download, validate). Restore is not available - it goes through change control."
    )]
    async fn unifi_backup_action(
        &self,
        Parameters(args): Parameters<ops::BackupActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_backup_action", Some(&args.controller), WRITE_TOOLS) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match ops::backup_action(args, client).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
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
        if let Err(error) = authorize_call(caller.as_ref(), "unifi_run_speed_test", Some(&args.controller), WRITE_TOOLS) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match ops::run_speed_test(args, client).await {
            Ok(json) => tool_result(Ok::<_, String>(json), ResultFormat::PrettyJson, RESULT_LIMITS),
            Err(error) => tool_error(error),
        }
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
        let served_names: BTreeSet<String> = all_tools
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        let registered_names: BTreeSet<String> = TOOL_NAMES.iter().map(|s| (*s).to_owned()).collect();

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
}
