//! # Password Hashing and Verification Module
//!
//! This module provides secure password hashing and verification functionality
//! using the Argon2 algorithm, which is the winner of the Password Hashing
//! Competition and recommended by OWASP for password storage.
//!
//! ## Security Features
//! - **Argon2id algorithm**: Memory-hard hashing resistant to GPU attacks
//! - **Random salts**: Each password gets a unique cryptographically random salt
//! - **Length validation**: Prevents DoS attacks via extremely long passwords
//! - **Constant-time verification**: Resistant to timing attacks
//!
//! ## Why Argon2?
//! Argon2 is superior to older algorithms like MD5, SHA1, or even bcrypt because:
//! - It's memory-hard (requires significant RAM, making parallelization expensive)
//! - It's resistant to GPU/ASIC attacks
//! - It's designed specifically for password hashing
//! - It won the Password Hashing Competition in 2015
//!

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::errors::ErrorMessage;

// CONSTANTS

/// Maximum allowed password length in characters
///
/// This limit serves multiple purposes:
/// 1. **DoS Prevention**: Extremely long passwords can cause excessive CPU/memory usage
/// 2. **Reasonable UX**: Most users don't use passwords longer than 64 characters
/// 3. **Security Balance**: Long enough for passphrases, short enough to prevent abuse
///
/// # Why 64?
/// - Argon2 has a maximum input length anyway
/// - 64 characters allows for strong passphrases (e.g., "correct horse battery staple" style)
/// - Prevents attackers from submitting megabyte-sized passwords to overload the server
///

const MAX_PASSWORD_LENGTH: usize = 64;

// PASSWORD HASHING

/// Hashes a password using Argon2id with a random salt
///
/// This function takes a plain-text password and returns a secure hash
/// suitable for storage in a database. The hash includes:
/// - Algorithm identifier (argon2id)
/// - Algorithm parameters (memory cost, time cost, parallelism)
/// - Random salt (unique for each password)
/// - The actual password hash
///
/// # Format of Output
/// The returned string follows the PHC string format:
/// ```text
/// $argon2id$v=19$m=19456,t=2,p=1$SALT$HASH
/// ```
/// Where:
/// - `argon2id` = Algorithm variant (hybrid of argon2i and argon2d)
/// - `v=19` = Argon2 version
/// - `m=19456` = Memory cost (19MB)
/// - `t=2` = Time cost (number of iterations)
/// - `p=1` = Parallelism factor
/// - `SALT` = Base64-encoded random salt
/// - `HASH` = Base64-encoded password hash
///
/// # Arguments
/// * `password` - The plain-text password to hash (accepts String, &str, etc.)
///
/// # Returns
/// * `Ok(String)` - The password hash in PHC string format
/// * `Err(ErrorMessage)` - If validation or hashing fails
///
/// # Errors
/// This function returns an error if:
/// - Password is empty (`ErrorMessage::EmptyPassword`)
/// - Password exceeds `MAX_PASSWORD_LENGTH` (`ErrorMessage::ExceededMaxPasswordLength`)
/// - Hashing operation fails (`ErrorMessage::HashingError`)
///
/// # Security Guarantees
/// - **Unique salts**: Each call generates a new cryptographically random salt
/// - **Non-deterministic**: Same password produces different hashes each time
/// - **One-way function**: Computationally infeasible to reverse
/// - **Slow by design**: Takes noticeable time to prevent brute-force attacks
///
/// # Performance Considerations
/// Argon2 is intentionally slow (typically 300-500ms on modern hardware).
/// This is a feature, not a bug! The slowness:
/// - Makes brute-force attacks impractical
/// - Has negligible impact on legitimate users (they only hash once per login)
/// - Significantly impacts attackers trying millions of guesses
///

pub fn hash(password: impl Into<String>) -> Result<String, ErrorMessage> {
    let password = password.into();

    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }

    // Generate a cryptographically secure random salt
    // Each password gets its own unique salt, preventing rainbow table attacks
    let salt = SaltString::generate(&mut OsRng);

    // Create Argon2 instance with default parameters
    // Default configuration uses argon2id variant with:
    // - Memory cost: 19MB (m=19456)
    // - Time cost: 2 iterations (t=2)
    // - Parallelism: 1 thread (p=1)
    let argon2 = Argon2::default();

    // Hash the password with the generated salt
    // This is an intentionally slow operation (typically 300-500ms)
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ErrorMessage::HashingError)?
        .to_string();

    Ok(password_hash)
}

// PASSWORD VERIFICATION

/// This function performs constant-time comparison of a plain-text password
/// against a previously hashed password. It extracts the salt and parameters
/// from the stored hash and re-hashes the input password using the same
/// configuration.

/// # Security Features
///
/// ## Constant-Time Comparison
/// The verification uses constant-time comparison to prevent timing attacks.
/// This means the function takes the same amount of time whether the password
/// is correct or incorrect, preventing attackers from learning information
/// about the password through timing analysis.
///
/// ## Salt Extraction
/// The function automatically extracts the salt from the stored hash, so you
/// don't need to store the salt separately. The hash is self-contained.
///
/// ## Parameter Extraction
/// The function uses the same Argon2 parameters (memory cost, time cost,
/// parallelism) that were used during hashing, ensuring consistent verification.
///
/// # Performance
/// Like hashing, verification is intentionally slow (300-500ms). This prevents
/// rapid brute-force attempts during login. Consider:
/// - Rate limiting login attempts (e.g., max 5 attempts per minute)
/// - Account lockout after repeated failures
/// - CAPTCHA after several failed attempts
///

pub fn verify_password(password: &str, hashed_password: &str) -> Result<bool, ErrorMessage> {
    // Validate: Password must not be empty
    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }

    // Validate: Password must not exceed maximum length
    // This prevents DoS attacks where attackers submit very long passwords
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }

    // Parse the stored hash string to extract salt and parameters
    // This validates the hash format and extracts all necessary information
    // for verification (algorithm, parameters, salt, hash)
    let parsed_hash: PasswordHash<'_> =
        PasswordHash::new(hashed_password).map_err(|_| ErrorMessage::InvalidHashFormat)?;

    // Create Argon2 instance with default parameters
    let argon2 = Argon2::default();

    // Verify the password against the hash
    // This is a constant-time operation to prevent timing attacks
    // Returns Ok(()) if password matches, Err(_) if it doesn't
    let password_matched = argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_or(false, |_| true); // Convert Result to bool: Ok(_) -> true, Err(_) -> false

    Ok(password_matched)
}
