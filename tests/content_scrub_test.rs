use gmail_proxy::scrub::content::ContentScrubber;
use regex::Regex;

fn test_scrubber() -> ContentScrubber {
    ContentScrubber::new(
        vec![
            Regex::new(r"\b\d{4,8}\b").unwrap(),
            Regex::new(r"(?i)verification code[:\s]+\S+").unwrap(),
            Regex::new(r"(?i)(one.time|temporary|security)\s+(code|password|pin)").unwrap(),
        ],
        vec![
            Regex::new(r"(?i)https?://[^\s]*/(reset|verify|confirm|auth|signin|login|activate)[^\s]*").unwrap(),
        ],
        vec![
            Regex::new(r"(?i)noreply@.*\.google\.com").unwrap(),
            Regex::new(r"(?i)no-reply@accounts\.google\.com").unwrap(),
            Regex::new(r"(?i)security@").unwrap(),
        ],
        true,
    )
}

fn scrubber_no_strip_links() -> ContentScrubber {
    ContentScrubber::new(
        vec![Regex::new(r"\b\d{4,8}\b").unwrap()],
        vec![Regex::new(r"(?i)https?://[^\s]*/(reset|verify|confirm|auth)[^\s]*").unwrap()],
        vec![Regex::new(r"(?i)noreply@.*\.google\.com").unwrap()],
        false,
    )
}

#[test]
fn test_blocked_sender_suppresses_message() {
    let scrubber = test_scrubber();
    assert!(scrubber.check_sender("noreply@accounts.google.com").is_blocked());
}

#[test]
fn test_blocked_sender_security_at() {
    let scrubber = test_scrubber();
    assert!(scrubber.check_sender("security@example.com").is_blocked());
}

#[test]
fn test_allowed_sender() {
    let scrubber = test_scrubber();
    assert!(!scrubber.check_sender("alice@example.com").is_blocked());
}

#[test]
fn test_blocked_sender_case_insensitive() {
    let scrubber = test_scrubber();
    assert!(scrubber.check_sender("NoReply@Accounts.Google.Com").is_blocked());
}

#[test]
fn test_redact_otp_code() {
    let scrubber = test_scrubber();
    let result = scrubber.scrub_body("Your code is 123456 please enter it.");
    assert!(!result.contains("123456"));
    assert!(result.contains("[REDACTED]"));
    assert!(result.contains("please enter it"));
}

#[test]
fn test_redact_verification_code() {
    let scrubber = test_scrubber();
    let result = scrubber.scrub_body("Your verification code: ABC123XYZ");
    assert!(!result.contains("ABC123XYZ"));
}

#[test]
fn test_redact_one_time_password() {
    let scrubber = test_scrubber();
    let result = scrubber.scrub_body("Use this one-time password to log in.");
    assert!(result.contains("[REDACTED]"));
}

#[test]
fn test_redact_auth_url() {
    let scrubber = scrubber_no_strip_links();
    let result = scrubber.scrub_body("Click here: https://example.com/auth/callback?token=abc123 to verify.");
    assert!(!result.contains("token=abc123"));
    assert!(result.contains("[REDACTED]"));
}

#[test]
fn test_redact_reset_url() {
    let scrubber = scrubber_no_strip_links();
    let result = scrubber.scrub_body("Reset: https://accounts.google.com/reset/pwd?id=xyz");
    assert!(!result.contains("id=xyz"));
}

#[test]
fn test_safe_url_preserved_when_strip_links_false() {
    let scrubber = scrubber_no_strip_links();
    let result = scrubber.scrub_body("Check https://example.com/blog/article for details.");
    assert!(result.contains("https://example.com/blog/article"));
}

#[test]
fn test_strip_all_links_when_enabled() {
    let scrubber = test_scrubber();
    let result = scrubber.scrub_body("Visit https://example.com/blog/article for details.");
    assert!(!result.contains("https://"));
    assert!(result.contains("[link removed]"));
}

#[test]
fn test_strip_http_links_too() {
    let scrubber = test_scrubber();
    let result = scrubber.scrub_body("Go to http://example.com for info.");
    assert!(!result.contains("http://"));
}

#[test]
fn test_multiple_redactions_in_one_body() {
    let scrubber = test_scrubber();
    let result = scrubber.scrub_body("Code: 123456. Also try https://evil.com/reset/pw?t=abc for recovery.");
    assert!(!result.contains("123456"));
    assert!(!result.contains("evil.com"));
}

#[test]
fn test_clean_body_unchanged() {
    let scrubber = scrubber_no_strip_links();
    let body = "Hi Alice, the meeting is at noon. See you there.";
    let result = scrubber.scrub_body(body);
    assert_eq!(result, body);
}

#[test]
fn test_sender_check_result_has_reason() {
    let scrubber = test_scrubber();
    let result = scrubber.check_sender("security@example.com");
    assert!(result.is_blocked());
    assert!(result.reason.is_some());
}
