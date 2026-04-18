//! Knowledge Base storage layer using Sled (embedded KV store).
//!
//! Provides caching with TTL for all intelligence sources.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

/// Knowledge Base backed by Sled.
pub struct KnowledgeBase {
    db: sled::Db,
}

impl KnowledgeBase {
    /// Open or create the KB at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path).context("Failed to open KB database")?;
        info!("KnowledgeBase opened");
        Ok(Self { db })
    }

    /// Open an in-memory KB (for testing).
    pub fn open_temp() -> Result<Self> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Self { db })
    }

    /// Store a value with TTL (time-to-live in seconds).
    #[tracing::instrument(skip(self, value), fields(key = %key))]
    pub fn put_with_ttl<V: Serialize>(
        &self,
        key: &str,
        value: &V,
        ttl_seconds: u64,
    ) -> Result<()> {
        let expires_at = chrono::Utc::now().timestamp() + ttl_seconds as i64;
        let wrapped = TimedValue {
            expires_at,
            data: value,
        };
        let bytes = serde_json::to_vec(&wrapped)?;
        self.db.insert(key.as_bytes(), bytes)?;
        debug!("Stored with TTL {}s", ttl_seconds);
        Ok(())
    }

    /// Get a value if it exists and hasn't expired.
    #[tracing::instrument(skip(self), fields(key = %key))]
    pub fn get<V: DeserializeOwned>(&self, key: &str) -> Result<Option<V>> {
        let Some(bytes) = self.db.get(key.as_bytes())? else {
            return Ok(None);
        };

        let wrapped: TimedValue<V> = serde_json::from_slice(&bytes)?;

        if chrono::Utc::now().timestamp() > wrapped.expires_at {
            debug!("Entry expired");
            self.db.remove(key.as_bytes())?;
            return Ok(None);
        }

        Ok(Some(wrapped.data))
    }

    /// Store without TTL (permanent - actually 10 years).
    pub fn put<V: Serialize>(&self, key: &str, value: &V) -> Result<()> {
        // Store with a very long TTL (10 years)
        self.put_with_ttl(key, value, 10 * 365 * 24 * 3600)
    }

    /// Remove a key.
    pub fn remove(&self, key: &str) -> Result<()> {
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    /// Flush to disk.
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

/// Wrapper for TTL-aware storage.
#[derive(Debug, Serialize, Deserialize)]
struct TimedValue<V> {
    expires_at: i64,
    data: V,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_get() {
        let kb = KnowledgeBase::open_temp().unwrap();
        kb.put("test", &"hello".to_string()).unwrap();
        let result: Option<String> = kb.get("test").unwrap();
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_ttl_expiration() {
        let kb = KnowledgeBase::open_temp().unwrap();
        // Put with 1 second TTL
        kb.put_with_ttl("test", &"value", 1).unwrap();
        // Should exist immediately
        let result: Option<String> = kb.get("test").unwrap();
        assert_eq!(result, Some("value".to_string()));
        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));
        let result: Option<String> = kb.get("test").unwrap();
        assert_eq!(result, None);
    }
}
