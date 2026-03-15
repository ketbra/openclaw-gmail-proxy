use regex::Regex;

pub struct ContentScrubber {
    otp_patterns: Vec<Regex>,
    url_strip_patterns: Vec<Regex>,
    blocked_sender_patterns: Vec<Regex>,
    strip_links: bool,
}

pub struct SenderCheckResult {
    pub blocked: bool,
    pub reason: Option<String>,
}

impl SenderCheckResult {
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }
}

impl ContentScrubber {
    pub fn new(
        otp_patterns: Vec<Regex>,
        url_strip_patterns: Vec<Regex>,
        blocked_sender_patterns: Vec<Regex>,
        strip_links: bool,
    ) -> Self {
        Self {
            otp_patterns,
            url_strip_patterns,
            blocked_sender_patterns,
            strip_links,
        }
    }

    pub fn check_sender(&self, from: &str) -> SenderCheckResult {
        for pattern in &self.blocked_sender_patterns {
            if pattern.is_match(from) {
                return SenderCheckResult {
                    blocked: true,
                    reason: Some(format!("Sender matches blocked pattern: {}", pattern)),
                };
            }
        }
        SenderCheckResult {
            blocked: false,
            reason: None,
        }
    }

    pub fn scrub_body(&self, body: &str) -> String {
        let mut result = body.to_string();

        // 1. Replace OTP pattern matches with [REDACTED]
        for pattern in &self.otp_patterns {
            result = pattern.replace_all(&result, "[REDACTED]").to_string();
        }

        // 2. Replace auth/reset URL pattern matches with [REDACTED]
        for pattern in &self.url_strip_patterns {
            result = pattern.replace_all(&result, "[REDACTED]").to_string();
        }

        // 3. If strip_links is true, replace ALL remaining URLs with [link removed]
        if self.strip_links {
            let url_pattern = Regex::new(r"https?://\S+").unwrap();
            result = url_pattern.replace_all(&result, "[link removed]").to_string();
        }

        result
    }
}
