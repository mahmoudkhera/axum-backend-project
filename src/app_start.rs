use axum::{
    Router,
    http::{
        HeaderValue, Method,
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    },
};
use dotenvy::dotenv;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;

use crate::{config::Config, db_handler::DBClient};

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Config,
    pub db_client: DBClient,
}
impl AppState {
    pub fn new(env: Config, db_client: DBClient) -> Self {
        Self {
            config: env,
            db_client,
        }
    }
}

async fn app_init() {
    dotenv().ok();

    let config = Config::init();
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("connection to DB is successful");
            pool
        }
        Err(error) => {
            println!("failed to connect the the DB due to {:?}", error);

            std::process::exit(1);
        }
    };

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:8000".parse::<HeaderValue>().unwrap())
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT]);

    let db_client = DBClient::new(pool);

    let app_state = AppState::new(config.clone(), db_client);

    let app = Router::new().layer(cors).with_state(app_state);

    println!("server is running on http://localhost:{}", &config.port);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &config.port))
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}
