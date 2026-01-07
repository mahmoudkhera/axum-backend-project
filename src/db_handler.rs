//! # Database Client Module
//!
//! This module provides a database abstraction layer for user management operations.
//! It defines a trait-based interface for all user-related database operations,
//! making it easy to test and swap implementations.
//!
//! ## Architecture
//! - `DBClient`: Wrapper around SQLx connection pool
//! - `UserExt`: Trait defining all user database operations
//! - Implementation uses SQLx's compile-time checked queries for type safety
//!
//! ## Key Features
//! - CRUD operations for users
//! - Email verification token management
//! - Password updates with automatic timestamp tracking
//! - Pagination support for user listings
//! - Type-safe query compilation with `query_as!` macro

use crate::model::{User, UserRole};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

// DATABASE CLIENT

/// Database client wrapper
///
/// Wraps a PostgreSQL connection pool and implements database operations
/// through the `UserExt` trait. This struct is cloneable because the
/// underlying connection pool uses Arc internally.
#[derive(Debug, Clone)]
pub struct DBClient {
    pool: Pool<Postgres>,
}

impl DBClient {
    pub fn new(pool: Pool<Postgres>) -> Self {
        DBClient { pool }
    }
}

// USER DATABASE OPERATIONS TRAIT
/// Trait defining all user-related database operations
///
/// This trait provides a clean interface for user management in the database.
/// All methods are asynchronous and return Result types for error handling.

#[async_trait]
pub trait UserExt {
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>, sqlx::Error>;
    async fn get_user_by_name(&self, name: &str) -> Result<Option<User>, sqlx::Error>;
    async fn get_user_by_email(&self, emial: &str) -> Result<Option<User>, sqlx::Error>;
    async fn get_user_by_token(&self, token: &str) -> Result<Option<User>, sqlx::Error>;

    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<User>, sqlx::Error>;

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        verification_token: T,
        token_expires_at: DateTime<Utc>,
    ) -> Result<User, sqlx::Error>;

    async fn get_user_count(&self) -> Result<i64, sqlx::Error>;

    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        name: T,
    ) -> Result<User, sqlx::Error>;

    async fn update_user_role(&self, user_id: Uuid, role: UserRole) -> Result<User, sqlx::Error>;

    async fn update_user_password(
        &self,
        user_id: Uuid,
        password: String,
    ) -> Result<User, sqlx::Error>;

    async fn verifed_token(&self, token: &str) -> Result<(), sqlx::Error>;

    async fn add_verifed_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error>;
}

// TRAIT IMPLEMENTATION

#[async_trait]
impl UserExt for DBClient {
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>, sqlx::Error> {
        // Prioritize lookup by different fields

        return sqlx::query_as!(
            User,
            r#"
            SELECT id, name, email, password, verified, created_at, updated_at,
                   verification_token, token_expires_at, role as "role: UserRole"
            FROM users
            WHERE id = $1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await;
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        // Prioritize lookup by different fields

        return sqlx::query_as!(
            User,
            r#"
            SELECT id, name, email, password, verified, created_at, updated_at,
                   verification_token, token_expires_at, role as "role: UserRole"
            FROM users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await;
    }
    async fn get_user_by_name(&self, token: &str) -> Result<Option<User>, sqlx::Error> {
        // Prioritize lookup by different fields

        return sqlx::query_as!(
            User,
            r#"
            SELECT id, name, email, password, verified, created_at, updated_at,
                   verification_token, token_expires_at, role as "role: UserRole"
            FROM users
            WHERE verification_token = $1
            "#,
            token
        )
        .fetch_optional(&self.pool)
        .await;
    }

    async fn get_user_by_token(&self, token: &str) -> Result<Option<User>, sqlx::Error> {
        // Prioritize lookup by different fields

        return sqlx::query_as!(
            User,
            r#"
            SELECT id, name, email, password, verified, created_at, updated_at,
                   verification_token, token_expires_at, role as "role: UserRole"
            FROM users
            WHERE verification_token = $1
            "#,
            token
        )
        .fetch_optional(&self.pool)
        .await;
    }

    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<User>, sqlx::Error> {
        let offset = (page - 1) * limit as u32;

        let users = sqlx::query_as!(
            User,
            r#"SELECT id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users 
            ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
            limit as i64,
            offset as i64,
        ).fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        verification_token: T,
        token_expires_at: DateTime<Utc>,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (name, email, password,verification_token, token_expires_at) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole"
            "#,
            name.into(),
            email.into(),
            password.into(),
            verification_token.into(),
            token_expires_at
        ).fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    async fn get_user_count(&self) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(r#"SELECT COUNT(*) FROM users"#)
            .fetch_one(&self.pool)
            .await?;

        Ok(count.unwrap_or(0))
    }

    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        new_name: T,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET name = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole"
            "#,
            new_name.into(),
            user_id
        ).fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_user_role(
        &self,
        user_id: Uuid,
        new_role: UserRole,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET role = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole"
            "#,
            new_role as UserRole,
            user_id
        ).fetch_one(&self.pool)
       .await?;

        Ok(user)
    }

    async fn update_user_password(
        &self,
        user_id: Uuid,
        new_password: String,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET password = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole"
            "#,
            new_password,
            user_id
        ).fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn verifed_token(&self, token: &str) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(
            r#"
            UPDATE users
            SET verified = true, 
                updated_at = Now(),
                verification_token = NULL,
                token_expires_at = NULL
            WHERE verification_token = $1
            "#,
            token
        )
        .execute(&self.pool)
        .await;

        Ok(())
    }

    async fn add_verifed_token(
        &self,
        user_id: Uuid,
        token: &str,
        token_expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(
            r#"
            UPDATE users
            SET verification_token = $1, token_expires_at = $2, updated_at = Now()
            WHERE id = $3
            "#,
            token,
            token_expires_at,
            user_id,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
