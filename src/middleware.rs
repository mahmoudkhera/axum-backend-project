//! # Authentication & Authorization Middleware
//!
//! This module provides middleware functions to protect API routes.
//! Use `auth` to verify users are logged in, and `role_check` to verify
//! they have the right permissions.
//!

use std::sync::Arc;

use axum::{
    Extension,
    extract::Request,
    http::{StatusCode, header},
    middleware::Next,
    response::IntoResponse,
};

use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_start::AppState,
    db_handler::UserExt,
    errors::{ErrorMessage, HttpError},
    model::{User, UserRole},
    utils::token,
};

// DATA STRUCTURES

/// Container for authenticated user data
///
/// After successful authentication, this struct is added to the request
/// so handlers can access the logged-in user's information.
///

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTAuthMiddeware {
    /// The authenticated user
    pub user: User,
}

// AUTHENTICATION MIDDLEWARE

/// Authenticates requests using JWT tokens
///
/// This middleware:
/// 1. Extracts JWT token from cookie or Authorization header
/// 2. Validates the token (signature, expiration)
/// 3. Loads the user from the database
/// 4. Makes user data available to handlers
///
/// # Token Sources (checked in order)
/// 1. Cookie named "token"
/// 2. Authorization header with "Bearer <token>"
///
/// # Returns
/// - Success: Continues to next middleware/handler with user data
/// - Failure: 401 Unauthorized error
///

pub async fn auth(
    cookie_jar: CookieJar,
    Extension(app_state): Extension<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, HttpError> {
    // Step 1: Extract token from cookie or Authorization header
    let cookies = cookie_jar
        .get("token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            // Fallback to Authorization header
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    // Extract token after "Bearer "
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value[7..].to_owned())
                    } else {
                        None
                    }
                })
        });

    // Step 2: Ensure token exists
    let token = cookies
        .ok_or_else(|| HttpError::unauthorized(ErrorMessage::TokenNotProvided.to_string()))?;

    // Step 3: Decode and validate JWT token
    let token_details = match token::decode_token(token, app_state.config.jwt_secret.as_bytes()) {
        Ok(token_details) => token_details,
        Err(_) => {
            return Err(HttpError::unauthorized(
                ErrorMessage::InvalidToken.to_string(),
            ));
        }
    };

    // Step 4: Parse user ID from token
    let user_id = uuid::Uuid::parse_str(&token_details.to_string())
        .map_err(|_| HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()))?;

    // Step 5: Fetch user from database
    let user = app_state
        .db_client
        .get_user_by_id(user_id)
        .await
        .map_err(|_| HttpError::unauthorized(ErrorMessage::UserNoLongerExist.to_string()))?;

    // Step 6: Verify user exists (account might be deleted)
    let user =
        user.ok_or_else(|| HttpError::unauthorized(ErrorMessage::UserNoLongerExist.to_string()))?;

    // Step 7: Store user in request extensions for handlers to access
    req.extensions_mut()
        .insert(JWTAuthMiddeware { user: user.clone() });

    // Step 8: Continue to next middleware or handler
    Ok(next.run(req).await)
}

// AUTHORIZATION MIDDLEWARE

/// Checks if authenticated user has required role(s)
///
/// This middleware must run AFTER `auth` middleware. It checks if the
/// user's role is in the list of allowed roles.
///
/// # HTTP Status Codes
/// - 401 Unauthorized: User not logged in (from `auth` middleware)
/// - 403 Forbidden: User logged in but lacks permission
pub async fn role_check(
    Extension(_app_state): Extension<Arc<AppState>>,
    req: Request,
    next: Next,
    required_roles: Vec<UserRole>,
) -> Result<impl IntoResponse, HttpError> {
    // Extract authenticated user from request extensions
    let user = req
        .extensions()
        .get::<JWTAuthMiddeware>()
        .ok_or_else(|| HttpError::unauthorized(ErrorMessage::UserNotAuthenticated.to_string()))?;

    // Check if user's role is in the allowed list
    if !required_roles.contains(&user.user.role) {
        return Err(HttpError::new(
            ErrorMessage::PermissionDenied.to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    // User has permission, continue to handler
    Ok(next.run(req).await)
}
