//! # HTTP Error Handling Module
//!
//! This module provides a comprehensive error handling system for Axum-based web applications.
//! It defines error types, HTTP status code mappings, and standardized JSON error responses.
//!
//! ## Key Components
//! - `ErrorResponse`: Standardized JSON structure for API error responses
//! - `ErrorMessage`: Enumeration of application-specific error types
//! - `HttpError`: Main error type with HTTP status codes and conversion utilities
//!
//! ## Design Philosophy
//! This module follows the principle of converting internal errors into user-friendly
//! HTTP responses with appropriate status codes, while maintaining type safety and
//! consistent error messaging across the application.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt;

// ERROR RESPONSE STRUCTURE
/// Standard JSON error response structure
///
/// This struct defines the consistent format for all error responses
/// sent to API clients. Using a standardized format makes it easier
/// for frontend applications to handle errors uniformly.

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

// APPLICATION ERROR MESSAGES
/// Enumeration of application-specific error types
///
/// This enum represents all possible domain-specific errors that can occur
/// in the application. Each variant corresponds to a specific error scenario
/// and provides a consistent error message through the `to_str()` method.
///
/// # Design Pattern
/// This enum serves as a type-safe way to handle errors without using raw strings
/// throughout the codebase. It ensures consistency in error messages and makes
/// it easier to update error text in one central location.
///
/// # Categories
/// - **Authentication Errors**: InvalidToken, TokenNotProvided, UserNotAuthenticated
/// - **Authorization Errors**: PermissionDenied
/// - **User Errors**: WrongCredentials, EmailExist, UserNoLongerExist
/// - **Password Errors**: EmptyPassword, HashingError, InvalidHashFormat, ExceededMaxPasswordLength
/// - **System Errors**: ServerError

#[derive(Debug, PartialEq)]
pub enum ErrorMessage {
    EmptyPassword,
    ExceededMaxPasswordLength(usize),
    InvalidHashFormat,
    HashingError,
    InvalidToken,
    ServerError,
    WrongCredentials,
    EmailExist,
    UserNoLongerExist,
    TokenNotProvided,
    PermissionDenied,
    UserNotAuthenticated,
}

impl ToString for ErrorMessage {
    fn to_string(&self) -> String {
        self.to_str().to_owned()
    }
}

impl ErrorMessage {
    fn to_str(&self) -> String {
        match self {
            ErrorMessage::ServerError => "Server Error. Please try again later".to_string(),
            ErrorMessage::WrongCredentials => "Email or password is wrong".to_string(),
            ErrorMessage::EmailExist => "A user with this email already exists".to_string(),
            ErrorMessage::UserNoLongerExist => {
                "User belonging to this token no longer exists".to_string()
            }
            ErrorMessage::EmptyPassword => "Password cannot be empty".to_string(),
            ErrorMessage::HashingError => "Error while hashing password".to_string(),
            ErrorMessage::InvalidHashFormat => "Invalid password hash format".to_string(),
            ErrorMessage::ExceededMaxPasswordLength(max_length) => {
                format!("Password must not be more than {} characters", max_length)
            }
            ErrorMessage::InvalidToken => "Authentication token is invalid or expired".to_string(),
            ErrorMessage::TokenNotProvided => {
                "You are not logged in, please provide a token".to_string()
            }
            ErrorMessage::PermissionDenied => {
                "You are not allowed to perform this action".to_string()
            }
            ErrorMessage::UserNotAuthenticated => {
                "Authentication required. Please log in.".to_string()
            }
        }
    }
}

// HTTP ERROR TYPE

/// Main error type for HTTP operations
///
/// This struct combines an error message with an HTTP status code,
/// providing a complete representation of HTTP errors in the application.
/// It implements Axum's `IntoResponse` trait, allowing it to be returned
/// directly from request handlers.
///
/// # Design Benefits
/// - Type-safe error handling with automatic HTTP response conversion
/// - Consistent error response format across all endpoints
/// - Easy to use in handler functions with the `?` operator
/// - Supports method chaining for common HTTP status codes
///
#[derive(Debug, Clone)]
pub struct HttpError {
    pub message: String,
    pub status: StatusCode,
}

impl HttpError {
    /// Creates a new HttpError with custom message and status code
    ///
    /// This is the most flexible constructor, allowing any status code
    /// and message combination. For common cases, prefer the convenience
    /// methods like `bad_request()`, `unauthorized()`, etc.
    ///
    /// # Arguments
    /// * `message` - Error message (can be String, &str, or ErrorMessage)
    /// * `status` - HTTP status code
    ///
    /// # Example
    /// ```rust
    /// let error = HttpError::new("Custom error", StatusCode::GONE);
    /// ``
    pub fn new(message: impl Into<String>, status: StatusCode) -> Self {
        HttpError {
            message: message.into(),
            status,
        }
    }

    /// Creates a 500 Internal Server Error
    ///
    /// Use for unexpected errors that shouldn't expose implementation details.
    /// This is the catch-all for unhandled errors.
    ///
    /// # Status Code: 500 INTERNAL_SERVER_ERROR
    ///
    /// # Example
    /// ```rust
    /// return Err(HttpError::server_error("Database connection failed"));
    /// ```

    pub fn server_error(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Creates a 400 Bad Request Error
    ///
    /// Use when client sends invalid data, malformed requests, or
    /// validation failures. This indicates the client needs to fix
    /// their request before retrying.
    ///
    /// # Status Code: 400 BAD_REQUEST
    ///
    /// # Example
    /// ```rust
    /// if body.email.is_empty() {
    ///     return Err(HttpError::bad_request("Email is required"));
    /// }
    /// ```
    pub fn bad_request(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    /// Creates a 409 Conflict Error
    ///
    /// Use when an operation fails due to a conflict with existing data,
    /// typically unique constraint violations (e.g., duplicate email).
    ///
    /// # Status Code: 409 CONFLICT
    ///
    /// # Example
    /// ```rust
    /// if email_exists {
    ///     return Err(HttpError::unique_constraint_violation(
    ///         ErrorMessage::EmailExist
    ///     ));
    /// }
    /// ```

    pub fn unique_constraint_violation(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::CONFLICT,
        }
    }

    /// Creates a 401 Unauthorized Error
    ///
    /// Use when authentication fails or is missing. This indicates
    /// the client needs to provide valid credentials.
    ///
    /// # Status Code: 401 UNAUTHORIZED
    ///
    /// # HTTP Semantics
    /// Despite the name, 401 means "unauthenticated" not "unauthorized".
    /// For authorization failures (permissions), use 403 Forbidden instead.
    ///
    /// # Example
    /// ```rust
    /// if !verify_password(&password, &user.hash) {
    ///     return Err(HttpError::unauthorized(ErrorMessage::WrongCredentials));
    /// }
    /// ```

    pub fn unauthorized(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    /// Converts the HttpError into an Axum HTTP Response
    ///
    /// This method creates a properly formatted JSON response with the
    /// error message and appropriate status code. The response body
    /// follows the ErrorResponse structure.
    ///
    /// # Response Format
    /// ```json
    /// {
    ///   "status": "fail",
    ///   "message": "Email or password is wrong"
    /// }
    /// ```
    ///
    /// # Returns
    /// An Axum Response with JSON body and HTTP status code
    ///
    /// # Note
    /// You typically don't call this directly; it's called automatically
    /// by Axum's IntoResponse implementation when you return an HttpError.

    pub fn into_http_response(self) -> Response {
        let json_response = Json(ErrorResponse {
            status: "fail".to_string(),
            message: self.message.clone(),
        });

        (self.status, json_response).into_response()
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HttpError: message: {}, status: {}",
            self.message, self.status
        )
    }
}

impl std::error::Error for HttpError {}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        self.into_http_response()
    }
}
