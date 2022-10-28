use crate::{AppState, TokenClaims};
use actix_web::{
    get, post,
    web::{Data, Json, ReqData},
    HttpResponse, Responder,
};
use actix_web_httpauth::extractors::basic::BasicAuth;
use argonautica::{Hasher, Verifier};
use chrono::NaiveDateTime;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{self, FromRow};

#[post("/user")]
async fn create_user(state: Data<AppState>) -> impl Responder {}

#[get("/auth")]
async fn basic_auth(state: Data<AppState>) -> impl Responder {}

#[post("/article")]
async fn create_article(state: Data<AppState>) -> impl Responder {}
