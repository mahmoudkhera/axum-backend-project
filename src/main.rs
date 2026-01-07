use axum_backend_prject::app_start;

#[tokio::main]
async fn main() {
    app_start::app_init().await;
}
