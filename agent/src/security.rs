//! Security module: rate limiting, IP whitelist, request validation

use common::{verify_auth_token, CommandRequest, Status};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Rate limiter for incoming requests
pub struct RateLimiter {
    /// Maximum requests per window
    max_requests: u32,
    /// Time window duration
    window: Duration,
    /// Request counts per IP
    counts: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    /// Blocked IPs (after too many failures)
    blocked: Mutex<HashMap<IpAddr, Instant>>,
    /// Block duration
    block_duration: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(60),
            counts: Mutex::new(HashMap::new()),
            blocked: Mutex::new(HashMap::new()),
            block_duration: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Check if an IP is allowed to make a request
    pub fn check(&self, ip: IpAddr) -> bool {
        // Check if IP is blocked
        {
            let blocked = self.blocked.lock().unwrap();
            if let Some(blocked_until) = blocked.get(&ip) {
                if Instant::now() < *blocked_until {
                    warn!("IP {} is blocked", ip);
                    return false;
                }
            }
        }

        // Check rate limit
        let mut counts = self.counts.lock().unwrap();
        let now = Instant::now();

        let entry = counts.entry(ip).or_insert((0, now));

        // Reset if window has passed
        if now.duration_since(entry.1) > self.window {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;

        if entry.0 > self.max_requests {
            warn!("Rate limit exceeded for IP {}", ip);
            return false;
        }

        true
    }

    /// Block an IP for repeated failures
    pub fn block(&self, ip: IpAddr) {
        let mut blocked = self.blocked.lock().unwrap();
        let until = Instant::now() + self.block_duration;
        blocked.insert(ip, until);
        warn!("Blocked IP {} for {:?}", ip, self.block_duration);
    }

    /// Clean up old entries
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Clean up counts
        {
            let mut counts = self.counts.lock().unwrap();
            counts.retain(|_, (_, time)| now.duration_since(*time) < self.window * 2);
        }

        // Clean up blocks
        {
            let mut blocked = self.blocked.lock().unwrap();
            blocked.retain(|_, until| now < *until);
        }
    }
}

/// IP whitelist checker
pub struct IpWhitelist {
    allowed: Vec<IpAddr>,
    allow_all: bool,
}

impl IpWhitelist {
    pub fn new(allowed_ips: &[String]) -> Self {
        if allowed_ips.is_empty() {
            return Self {
                allowed: vec![],
                allow_all: true,
            };
        }

        let allowed: Vec<IpAddr> = allowed_ips
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        info!("IP whitelist configured with {} addresses", allowed.len());

        Self {
            allowed,
            allow_all: false,
        }
    }

    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        if self.allow_all {
            return true;
        }

        let allowed = self.allowed.contains(ip);
        if !allowed {
            warn!("IP {} not in whitelist", ip);
        }
        allowed
    }
}

/// Request validator
pub struct RequestValidator {
    psk: [u8; 32],
    /// Timestamp tolerance in seconds
    timestamp_tolerance: u64,
    /// Recently seen request IDs (anti-replay)
    seen_ids: Mutex<HashMap<u32, Instant>>,
}

impl RequestValidator {
    pub fn new(psk: [u8; 32]) -> Self {
        Self {
            psk,
            timestamp_tolerance: 600,
            seen_ids: Mutex::new(HashMap::new()),
        }
    }

    /// Validate a request
    pub fn validate(&self, request: &CommandRequest) -> Result<(), Status> {
        // Check protocol version
        if request.version != common::PROTOCOL_VERSION {
            warn!(
                "Invalid protocol version: {} (expected {})",
                request.version,
                common::PROTOCOL_VERSION
            );
            return Err(Status::InvalidCommand);
        }

        // Check timestamp
        if !request.is_timestamp_valid(self.timestamp_tolerance) {
            warn!("Request timestamp out of range");
            return Err(Status::Timeout);
        }

        // Check for replay
        {
            let mut seen = self.seen_ids.lock().unwrap();
            let now = Instant::now();

            // Clean up old entries
            seen.retain(|_, time| now.duration_since(*time) < Duration::from_secs(120));

            if seen.contains_key(&request.request_id) {
                warn!("Duplicate request ID: {}", request.request_id);
                return Err(Status::InvalidCommand);
            }

            seen.insert(request.request_id, now);
        }

        // Verify authentication token
        if !verify_auth_token(request, &self.psk) {
            warn!("Authentication failed for request {}", request.request_id);
            return Err(Status::AuthFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(3);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip)); // Exceeded
    }

    #[test]
    fn test_ip_whitelist() {
        let whitelist = IpWhitelist::new(&["192.168.1.1".to_string()]);
        assert!(whitelist.is_allowed(&"192.168.1.1".parse().unwrap()));
        assert!(!whitelist.is_allowed(&"192.168.1.2".parse().unwrap()));

        // Empty whitelist allows all
        let allow_all = IpWhitelist::new(&[]);
        assert!(allow_all.is_allowed(&"10.0.0.1".parse().unwrap()));
    }
}
