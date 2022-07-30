use crate::{erro::AppError, models::LoginRequest, repositories::UserRepository};
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use axum::{http::StatusCode, Extension, Json};

/// Login API Endpoint
/// This endpoint provide a way to authenticate into the system and
/// be capable to make requests on the protected routes
#[allow(clippy::unused_async)]
pub async fn login(
    Json(payload): Json<LoginRequest>,
    Extension(user_repository): Extension<UserRepository>,
) -> Result<StatusCode, AppError> {
    let argon = Argon2::default();
    let user_result = match user_repository
        .get_user_by_username(payload.username.clone())
        .await
    {
        Ok(user) => user,
        Err(_) => {
            return Err(AppError::BadCredentials);
        }
    };
    let usr_password = match PasswordHash::new(&user_result.passwd_hash) {
        Ok(hash) => hash,
        Err(_) => {
            tracing::error!("Password integrity violation detected: Invalid hash");
            return Err(AppError::ServerError);
        }
    };
    match argon.verify_password(payload.password.as_bytes(), &usr_password) {
        Ok(()) => Ok(StatusCode::OK),
        Err(_) => {
            tracing::debug!("User login failed for user: {}", user_result.username);
            Err(AppError::BadCredentials)
        }
    }
}
