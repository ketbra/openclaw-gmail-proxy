use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Instant;
use anyhow::{Result, anyhow};

use crate::gmail::types::TokenResponse;

pub struct TokenManager {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    token_url: String,
    http_client: reqwest::Client,
    cached: Arc<RwLock<Option<CachedToken>>>,
}

struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

/// Safety margin: refresh tokens 5 minutes before they actually expire.
const SAFETY_MARGIN_SECS: u64 = 5 * 60;

impl TokenManager {
    pub fn new(
        client_id: String,
        client_secret: String,
        refresh_token: String,
        token_url: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            refresh_token,
            token_url,
            http_client: reqwest::Client::new(),
            cached: Arc::new(RwLock::new(None)),
        }
    }

    /// Return a valid access token, refreshing if necessary.
    pub async fn get_token(&self) -> Result<String> {
        // Check cache first
        {
            let guard = self.cached.read().await;
            if let Some(cached) = guard.as_ref() {
                if Instant::now() < cached.expires_at {
                    return Ok(cached.access_token.clone());
                }
            }
        }

        // Cache miss or expired — refresh
        self.refresh().await
    }

    async fn refresh(&self) -> Result<String> {
        let body = format!(
            "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={}",
            self.client_id, self.client_secret, self.refresh_token,
        );

        let resp = self
            .http_client
            .post(&self.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Token refresh failed with status {}: {}",
                status,
                text
            ));
        }

        let token_resp: TokenResponse = resp.json().await?;

        let expires_at = if token_resp.expires_in > SAFETY_MARGIN_SECS {
            Instant::now()
                + std::time::Duration::from_secs(token_resp.expires_in - SAFETY_MARGIN_SECS)
        } else {
            // Token expires sooner than the safety margin; use it but mark as
            // expiring immediately so we re-fetch next time.
            Instant::now()
        };

        let access_token = token_resp.access_token.clone();

        {
            let mut guard = self.cached.write().await;
            *guard = Some(CachedToken {
                access_token: access_token.clone(),
                expires_at,
            });
        }

        Ok(access_token)
    }

    /// Remaining seconds until the cached token expires, if any.
    /// Intended for the health endpoint.
    pub async fn expires_in_secs(&self) -> Option<u64> {
        let guard = self.cached.read().await;
        guard.as_ref().map(|c| {
            let now = Instant::now();
            if c.expires_at > now {
                (c.expires_at - now).as_secs()
            } else {
                0
            }
        })
    }

    /// Whether the cached token is present and not yet expired.
    pub async fn is_valid(&self) -> bool {
        let guard = self.cached.read().await;
        match guard.as_ref() {
            Some(cached) => Instant::now() < cached.expires_at,
            None => false,
        }
    }
}
