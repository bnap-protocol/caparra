//! [`PricedTools`]: an rmcp `ServerHandler` that prices the tools of
//! another one.
//!
//! It forwards every handler method, logging (`set_level`) included, which
//! rmcp marks deprecated (SEP-2577).
#![allow(deprecated)]

use std::borrow::Cow;
use std::sync::Arc;

use axum::http::request::Parts;
use rmcp::ErrorData as McpError;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CancelTaskParams, CancelledNotificationParam,
    CompleteRequestParams, CompleteResult, CustomNotification, CustomRequest, CustomResult,
    DiscoverResult, GetPromptRequestParams, GetPromptResponse, GetTaskParams, GetTaskResult,
    InitializeRequestParams, InitializeResult, ListPromptsResult, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ProgressNotificationParam,
    ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse, ServerConfig,
    SetLevelRequestParams, SubscribeRequestParams, SubscriptionFilter, Tool,
    UnsubscribeRequestParams, UpdateTaskParams,
};
use rmcp::service::{NotificationContext, RequestContext, SubscriptionContext};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{RoleServer, ServerHandler};

use crate::gate::{Gate, Presented};
use crate::strict::{StrictConfig, StrictJson, strict_json};
use crate::wire;

/// Wraps an rmcp server handler and runs every call to a priced tool
/// through the [`Gate`]: no credential gets a `-32042` error with an
/// offer, a valid credential runs the tool once and returns its result
/// with the receipt in `result._meta`. Free tools and every other request
/// go to the inner handler unchanged.
///
/// The credential keys are removed from `_meta` before the inner handler
/// sees the request: a tool never reads a bearer secret.
#[derive(Debug, Clone)]
pub struct PricedTools<H> {
    inner: H,
    gate: Arc<Gate>,
}

impl<H> PricedTools<H> {
    /// Prices `inner`'s tools as `gate` is configured.
    pub fn new(inner: H, gate: Arc<Gate>) -> Self {
        Self { inner, gate }
    }

    /// The inner handler.
    pub fn inner(&self) -> &H {
        &self.inner
    }

    /// The gate.
    pub fn gate(&self) -> &Arc<Gate> {
        &self.gate
    }
}

/// True when the HTTP layer marked the message as read strictly.
fn strict(ctx: &RequestContext<RoleServer>) -> bool {
    ctx.extensions
        .get::<Parts>()
        .is_some_and(|p| p.extensions.get::<StrictJson>().is_some())
}

/// Takes both credential keys out of `_meta`.
fn take_credentials(ctx: &mut RequestContext<RoleServer>) -> Presented {
    let m = &mut (ctx.meta.0).0;
    Presented {
        bnap: m.remove(wire::CREDENTIAL),
        mpp: m.remove(wire::MPP_CREDENTIAL),
    }
}

/// An axum router serving `inner` priced by `gate` at `path`, over rmcp's
/// streamable HTTP transport (stateless, JSON responses), behind the
/// strict JSON layer. `config` is rmcp's server configuration, for the
/// allowed hosts; its `legacy_session_mode` is turned off.
pub fn router<H, F>(
    path: &str,
    gate: Arc<Gate>,
    mut config: StreamableHttpServerConfig,
    strict_config: StrictConfig,
    inner: F,
) -> axum::Router
where
    H: ServerHandler + Send + 'static,
    F: Fn() -> H + Send + Sync + 'static,
{
    config.legacy_session_mode = false;
    config.json_response = true;
    let service = StreamableHttpService::new(
        move || Ok(PricedTools::new(inner(), gate.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    axum::Router::new()
        .nest_service(path, service)
        .layer(axum::middleware::from_fn_with_state(
            strict_config,
            strict_json,
        ))
}

impl<H: ServerHandler> ServerHandler for PricedTools<H> {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if self.gate.price(&request.name).is_none() {
            return self.inner.call_tool(request, context).await;
        }
        let presented = take_credentials(&mut context);
        let strict = strict(&context);
        let inner = &self.inner;
        self.gate
            .call(request, presented, strict, move |p| {
                inner.call_tool(p, context)
            })
            .await
    }

    async fn ping(&self, context: RequestContext<RoleServer>) -> Result<(), McpError> {
        self.inner.ping(context).await
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        self.inner.initialize(request, context).await
    }

    fn negotiate_initialize(
        &self,
        request: &InitializeRequestParams,
    ) -> Result<InitializeResult, McpError> {
        self.inner.negotiate_initialize(request)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner.supported_protocol_versions()
    }

    async fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, McpError> {
        self.inner.discover(context).await
    }

    async fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, McpError> {
        self.inner.complete(request, context).await
    }

    async fn set_level(
        &self,
        request: SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.inner.set_level(request, context).await
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, McpError> {
        self.inner.get_prompt(request, context).await
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        self.inner.list_prompts(request, context).await
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        self.inner.list_resources(request, context).await
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        self.inner.list_resource_templates(request, context).await
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        self.inner.read_resource(request, context).await
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.inner.accepted_subscription_filter(requested)
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), McpError> {
        self.inner.listen(context).await
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.inner.subscribe(request, context).await
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.inner.unsubscribe(request, context).await
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.inner.list_tools(request, context).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, McpError> {
        self.inner.on_custom_request(request, context).await
    }

    async fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.inner.on_cancelled(notification, context).await;
    }

    async fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        context: NotificationContext<RoleServer>,
    ) {
        self.inner.on_progress(notification, context).await;
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        self.inner.on_initialized(context).await;
    }

    async fn on_roots_list_changed(&self, context: NotificationContext<RoleServer>) {
        self.inner.on_roots_list_changed(context).await;
    }

    async fn on_custom_notification(
        &self,
        notification: CustomNotification,
        context: NotificationContext<RoleServer>,
    ) {
        self.inner
            .on_custom_notification(notification, context)
            .await;
    }

    fn get_info(&self) -> ServerConfig {
        self.inner.get_info()
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        self.inner.get_task(request, context).await
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.inner.update_task(request, context).await
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.inner.cancel_task(request, context).await
    }
}
