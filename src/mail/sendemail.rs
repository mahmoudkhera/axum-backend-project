//! # Email Service Module
//!
//! Sends HTML emails using SMTP (Simple Mail Transfer Protocol).
//! Supports email templates with dynamic content replacement.
//!

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{SinglePart, header},
    transport::smtp::authentication::Credentials,
};
use std::env;
use tokio::fs;

/// Sends an HTML email using SMTP
///
/// This function:
/// 1. Loads an HTML email template from a file
/// 2. Replaces placeholders with actual values
/// 3. Sends the email via SMTP
///
pub async fn send_email(
    to_email: &str,
    subject: &str,
    template_path: &str,
    placeholders: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let smtp_server = env::var("SMTP_SERVER").unwrap();
    let smtp_port: u16 = env::var("SMTP_PORT").unwrap().parse().unwrap();
    let smtp_username = env::var("SMTP_USERNAME").unwrap();
    let smtp_password = env::var("SMTP_PASSWORD").unwrap();
    let from_address = env::var("SMTP_FROM_ADDRESS").unwrap();

    let mut html = fs::read_to_string(template_path).await.unwrap();

    for (k, v) in placeholders {
        html = html.replace(k, v);
    }

    let email = Message::builder()
        .from(from_address.parse().unwrap())
        .to(to_email.parse().unwrap())
        .subject(subject)
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_HTML)
                .body(html),
        )
        .unwrap();

    let creds = Credentials::new(smtp_username, smtp_password);
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_server)
        .unwrap()
        .credentials(creds)
        .port(smtp_port)
        .build();

    mailer.send(email).await?;
    Ok(())
}

/*
IMPORTANT NOTES:

1. **Security**: Never commit SMTP credentials to git. Use .env files and add to .gitignore
2. **App Passwords**: Gmail requires app-specific passwords, not your regular password
3. **Rate Limits**: Email providers have sending limits (Gmail: 500/day for free accounts)
4. **Templates**: Store templates in a dedicated folder (e.g., templates/)
5. **Error Handling**: Current code uses .unwrap() which will panic on errors - improve for production
6. **Testing**: Use a mock SMTP server for tests, don't send real emails in tests
7. **Async**: This function is async - call it with .await
8. **TLS/SSL**: STARTTLS encrypts the connection for security

COMMON PLACEHOLDERS:
- {{name}} - User's name
- {{email}} - User's email
- {{link}} - Verification or action link
- {{token}} - Verification token
- {{date}} - Current date/time
- {{company}} - Your company name
- {{expires}} - Link expiration time
*/
