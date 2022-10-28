use actix_web::{
    dev::ServiceRequest,
    error::Error,
    web::{self, Data},
    App, HttpMessage, HttpServer,
};
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use actix_web_httpauth::{
    extractors::{
        bearer::{self, BearerAuth},
        AuthenticationError,
    },
    middleware::HttpAuthentication,
};
use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub struct AppState {
    db: Pool<Postgres>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");

    HttpServer::new(move || App::new().app_data(Data::new(AppState { db: pool.clone() })))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
