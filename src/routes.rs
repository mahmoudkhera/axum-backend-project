use std::sync::Arc;

use axum::{Extension, Router, middleware};
use tower_http::trace::TraceLayer;

use crate::{
    app_start::AppState,
    handler::{auth_endpoint, user_handler},
    middleware::auth,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    let api_route = Router::new()
        .nest("/auth", auth_endpoint::auth_handler())
        .nest(
            "/users",
            user_handler::users_handler().layer(middleware::from_fn(auth)),
        )
        .layer(TraceLayer::new_for_http())
        .layer(Extension(app_state));

    Router::new().nest("/api", api_route)
}
