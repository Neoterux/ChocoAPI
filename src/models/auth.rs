use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Authorization Token
/// This token is the JWT token that would be returned
/// to the user when the authentication was successfully.
#[derive(Serialize)]
pub struct AuthToken {
    pub access_token: String,
    pub refresh_token: String,
}
