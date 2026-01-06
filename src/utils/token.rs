//! # JWT Token Management Module
//!
//! This module provides JSON Web Token (JWT) creation and validation for
//! user authentication and authorization. JWTs are used to maintain stateless
//! authentication sessions across HTTP requests.
//!
//! ## What is a JWT?
//! A JWT is a compact, URL-safe token format that consists of three parts:
//! 1. **Header**: Algorithm and token type
//! 2. **Payload**: Claims (user data, expiration, etc.)
//! 3. **Signature**: Cryptographic signature to verify authenticity
//!
//! ## Typical Flow
//! ```text
//! 1. User logs in with credentials
//! 2. Server validates credentials
//! 3. Server creates JWT with create_token()
//! 4. Client stores JWT (localStorage, cookie, etc.)
//! 5. Client includes JWT in Authorization header for requests
//! 6. Server validates JWT with decode_token()
//! 7. Server processes authenticated request
//! ```

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::{ErrorMessage, HttpError};

// JWT CLAIMS STRUCTURE

/// JWT token claims (payload data)
///
/// This structure defines the data stored inside the JWT token.
/// These claims follow the JWT specification (RFC 7519) and include
/// both standard claims and custom data.
///
/// # Standard JWT Claims
/// - `sub` (Subject): Identifies the user (typically user ID)
/// - `iat` (Issued At): Timestamp when token was created
/// - `exp` (Expiration): Timestamp when token expires
///
/// # Additional Claims (Not Used Here)
/// The JWT spec also defines optional claims you could add:
/// - `iss` (Issuer): Who created the token
/// - `aud` (Audience): Who the token is intended for
/// - `nbf` (Not Before): Token not valid before this time
/// - `jti` (JWT ID): Unique identifier for the token

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject: User ID that owns this token
    pub sub: String,

    /// Issued At: Unix timestamp when token was created
    /// Stored as seconds since Unix epoch (January 1, 1970).
    pub iat: usize,

    /// Expiration: Unix timestamp when token expires
    ///
    pub exp: usize,
}

// TOKEN CREATION

/// Creates a signed JWT token for a user
///
/// Generates a JSON Web Token containing the user's ID and expiration time,
/// signed with HMAC-SHA256 algorithm. This token can be sent to the client
/// and used for subsequent authenticated requests.
///
/// # Arguments
/// * `user_id` - Unique identifier for the user (typically UUID as string)
/// * `secret` - Secret key for signing the token (from environment variable)
/// * `expires_in_seconds` - Token lifetime in seconds (NOT minutes, despite the variable name!)
///
/// # Returns
/// * `Ok(String)` - Base64-encoded JWT token
/// * `Err(jsonwebtoken::errors::Error)` - If token creation fails
///
/// # Token Structure
/// The generated token has three parts separated by dots:
/// ```text
/// HEADER.PAYLOAD.SIGNATURE
/// ```
///
/// **Header** (Base64-encoded JSON):
/// ```json
/// {
///   "alg": "HS256",
///   "typ": "JWT"
/// }
/// ```
///
/// **Payload** (Base64-encoded JSON):
/// ```json
/// {
///   "sub": "user-id-here",
///   "iat": 1704470400,
///   "exp": 1704474000
/// }
/// ```
///
/// **Signature**:
/// HMACSHA256(base64(header) + "." + base64(payload), secret)
///
/// # Security Notes
///
/// ## Secret Key Management
/// The `secret` parameter is critical for security:
/// - Must be cryptographically random
/// - Minimum 256 bits (32 bytes) for HS256
/// - Store in environment variables, never hardcode
/// - Rotate periodically (invalidates all existing tokens)
/// - Use different secrets for dev/staging/prod
///
/// ## Token Expiration
/// Choose expiration times based on security requirements:
/// - **Short-lived (15-60 min)**: High security, better UX with refresh tokens
/// - **Long-lived (24 hours+)**: Convenient but higher risk if stolen
/// - **Refresh token pattern**: Short access token + long refresh token
///
/// Common patterns:
/// - Access token: 15 minutes
/// - Refresh token: 7 days
/// - Remember me: 30 days
///
/// ## Token Storage on Client
/// - **localStorage**: Simple but vulnerable to XSS
/// - **httpOnly cookie**: Safer, immune to XSS, but vulnerable to CSRF
/// - **sessionStorage**: More secure than localStorage, cleared on tab close
/// - **memory only**: Most secure, lost on page refresh
///

pub fn create_token(
    user_id: &str,
    secret: &[u8],
    expires_in_seconds: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    // Validate: user_id must not be empty
    if user_id.is_empty() {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidSubject.into());
    }

    // Get current timestamp
    let now = Utc::now();
    let iat = now.timestamp() as usize;

    // Calculate expiration timestamp

    let exp = (now + Duration::seconds(expires_in_seconds)).timestamp() as usize;

    // Build the token claims (payload)
    let claims = TokenClaims {
        sub: user_id.to_string(),
        iat,
        exp,
    };

    // Encode and sign the token
    // Header::default() uses HS256 algorithm
    jsonwebtoken::encode(
        &Header::default(), // Uses {"alg": "HS256", "typ": "JWT"}
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

// TOKEN VALIDATION

/// Decodes and validates a JWT token, extracting the user ID
///
/// Takes a JWT token string, verifies its signature and expiration,
/// and returns the user ID if the token is valid. This function performs
/// comprehensive validation including signature verification and expiration
/// checking.
///

/// # Validation Steps
/// This function automatically validates:
/// 1. **Token format**: Must be three base64-encoded parts separated by dots
/// 2. **Signature**: Must match the expected signature for the payload
/// 3. **Algorithm**: Must be HS256 (prevents algorithm substitution attacks)
/// 4. **Expiration**: Token must not be expired (exp claim checked)
/// 5. **Claims structure**: Must deserialize to TokenClaims
///
/// # Common Failure Reasons
/// - **Invalid signature**: Token was tampered with or wrong secret used
/// - **Expired token**: Current time is past the exp claim
/// - **Malformed token**: Missing parts or invalid base64 encoding
/// - **Algorithm mismatch**: Token uses different algorithm than HS256
/// - **Wrong secret**: Different secret used for creation vs validation
///
/// # Security Considerations
///
/// ## Secret Key Must Match
/// The secret used for validation must be the EXACT same secret used
/// for creation. Even one byte difference will cause validation failure.
///
/// ## Timing Attack Resistance
/// The underlying jsonwebtoken library uses constant-time comparison
/// for signature verification, preventing timing attacks.
///
/// ## Token Revocation
/// JWTs are stateless - once issued, they're valid until expiration.
/// For early revocation, you need additional mechanisms:
/// - Maintain a blacklist of revoked tokens in Redis
/// - Use shorter expiration times with refresh tokens
/// - Include a token version number in the database

pub fn decode_token<T: Into<String>>(token: T, secret: &[u8]) -> Result<String, HttpError> {
    // Attempt to decode and validate the token
    // This performs all validation checks automatically:
    // - Signature verification
    // - Expiration checking
    // - Format validation
    let decode = jsonwebtoken::decode::<TokenClaims>(
        &token.into(),
        &DecodingKey::from_secret(secret),
        &Validation::new(Algorithm::HS256), // Only accept HS256 tokens
    );

    // Handle the result
    match decode {
        Ok(token) => {
            // Token is valid - extract and return the user ID
            Ok(token.claims.sub)
        }
        Err(_) => {
            // Token is invalid - return 401 Unauthorized error
            // Note: We don't expose the specific error reason to the client
            // for security reasons (prevents information leakage)
            Err(HttpError::new(
                ErrorMessage::InvalidToken.to_string(),
                StatusCode::UNAUTHORIZED,
            ))
        }
    }
}
