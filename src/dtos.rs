//! # User Authentication and Management DTOs
//!
//! This module contains Data Transfer Objects (DTOs) for user authentication,
//! registration, and profile management. All structs include validation rules
//! to ensure data integrity before processing.
//!
//! ## Key Features
//! - User registration with password confirmation
//! - User login with email/password
//! - Profile updates (name, role, password)
//! - Email verification
//! - Password reset flow
//! - Paginated user queries
//! - Sanitized user responses (excludes sensitive data)

use chrono::{DateTime, Utc};
use core::str;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::model::{User, UserRole};

/// User registration data with password confirmation

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct RegisterUser {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
    #[validate(
        length(min = 1, message = "Password is required"),
        length(min = 6, message = "Password must be at least 6 characters")
    )]
    pub password: String,

    #[validate(
        length(min = 1, message = "Confirm Password is required"),
        must_match(other = "password", message = "passwords do not match")
    )]
    #[serde(rename = "passwordConfirm")]
    pub password_confirm: String,
}

/// User login credentials

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoginUser {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
    #[validate(
        length(min = 1, message = "Password is required"),
        length(min = 6, message = "Password must be at least 6 characters")
    )]
    pub password: String,
}

/// Query parameters for paginated requests

#[derive(Serialize, Deserialize, Validate)]
pub struct RequestQuery {
    #[validate(range(min = 1))]
    pub page: Option<usize>,
    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
}

// USER DATA REPRESENTATION

/// Filtered user data for API responses
///
/// This struct represents a sanitized version of the User model,
/// excluding sensitive information like password hashes. Use this
/// for all user data sent to clients.

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub verified: bool,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl FilterUser {
    pub fn filter_user(user: &User) -> Self {
        FilterUser {
            id: user.id.to_string(),
            name: user.name.to_owned(),
            email: user.email.to_owned(),
            verified: user.verified,
            role: user.role.to_str().to_string(),
            created_at: user.created_at.unwrap(),
            updated_at: user.updated_at.unwrap(),
        }
    }

    pub fn filter_users(user: &[User]) -> Vec<FilterUser> {
        user.iter().map(FilterUser::filter_user).collect()
    }
}

// API RESPONSE STRUCTURES

/// Wrapper for single user data in responses
#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub user: FilterUser,
}

/// Standard response format for single user operations

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub status: String,
    pub data: UserData,
}

/// Response format for user list endpoints

#[derive(Debug, Serialize, Deserialize)]
pub struct UserListResponse {
    pub status: String,
    pub users: Vec<FilterUser>,
    pub results: i64,
}

/// Response after successful authentication

#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginResponse {
    pub status: String,
    pub token: String,
}

/// Generic response structure

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub status: &'static str,
    pub message: String,
}

// USER UPDATE OPERATIONS

/// Request body for updating user's display name
#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct NameUpdate {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
}

/// Request body for updating user's role

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RoleUpdate {
    #[validate(custom = "validate_user_role")]
    pub role: UserRole,
}
/// Custom validator for UserRole

fn validate_user_role(role: &UserRole) -> Result<(), validator::ValidationError> {
    match role {
        UserRole::Admin | UserRole::User => Ok(()),
    }
}

/// Request body for password change

#[derive(Debug, Validate, Default, Clone, Serialize, Deserialize)]
pub struct UserPasswordUpdate {
    #[validate(
        length(min = 1, message = "New password is required."),
        length(min = 6, message = "new password must be at least 6 characters")
    )]
    pub new_password: String,

    #[validate(
        length(min = 1, message = "New password confirm is required."),
        length(
            min = 6,
            message = "new password confirm must be at least 6 characters"
        ),
        must_match(other = "new_password", message = "new passwords do not match")
    )]
    pub new_password_confirm: String,

    #[validate(
        length(min = 1, message = "Old password is required."),
        length(min = 6, message = "Old password must be at least 6 characters")
    )]
    pub old_password: String,
}

// EMAIL VERIFICATION & PASSWORD RESET

/// Query parameter for email verification
///
/// Used in email verification links sent to users after registration.
#[derive(Serialize, Deserialize, Validate)]
pub struct VerifyEmailQuery {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
}

/// Request body for initiating password reset

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct ForgotPasswordRequest {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
}

/// Request body for completing password reset

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,

    #[validate(
        length(min = 1, message = "New password is required."),
        length(min = 6, message = "new password must be at least 6 characters")
    )]
    pub new_password: String,

    #[validate(
        length(min = 1, message = "New password confirm is required."),
        length(
            min = 6,
            message = "new password confirm must be at least 6 characters"
        ),
        must_match(other = "new_password", message = "new passwords do not match")
    )]
    pub new_password_confirm: String,
}
