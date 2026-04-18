//! IntelCollector - Main orchestration module for intelligence gathering.
//!
//! Aggregates data from all sources into a unified TargetProfile.

use crate::intel::{
    db::KnowledgeBase,
    sources::*,
    types::*,
};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, instrument, warn};

/// Main intelligence collector.
pub struct IntelCollector {
    kb: KnowledgeBase,
    semaphore: Arc<Semaphore>,
    // Source clients
    nvd: Option<NvdClient>,
    shodan: Option<ShodanClient>,
    fofa: Option<FofaClient>,
    crtsh: CrtShClient,
    wayback: WaybackClient,
    ubuntu: UbuntuUsnClient,
    redhat: RedHatClient,
    debian: DebianClient,
    arch: ArchClient,
    github: Option<GitHubClient>,
}

impl IntelCollector {
    /// Create a new IntelCollector with the given KB path.
    pub fn new<P: AsRef<std::path::Path>>(kb_path: P) -> Result<Self> {
        let kb = KnowledgeBase::open(kb_path)?;

        // Initialize optional clients
        let nvd = NvdClient::new().ok();
        let shodan = ShodanClient::new().ok();
        let fofa = FofaClient::new().ok();
        let github = GitHubClient::new().ok();

        // Initialize required clients
        let crtsh = CrtShClient::new()?;
        let wayback = WaybackClient::new()?;
        let ubuntu = UbuntuUsnClient::new()?;
        let redhat = RedHatClient::new()?;
        let debian = DebianClient::new()?;
        let arch = ArchClient::new()?;

        Ok(Self {
            kb,
            semaphore: Arc::new(Semaphore::new(5)), // Max 5 concurrent requests
            nvd,
            shodan,
            fofa,
            crtsh,
            wayback,
            ubuntu,
            redhat,
            debian,
            arch,
            github,
        })
    }

    /// Create with in-memory KB (for testing).
    pub fn new_temp() -> Result<Self> {
        let kb = KnowledgeBase::open_temp()?;

        Ok(Self {
            kb,
            semaphore: Arc::new(Semaphore::new(5)),
            nvd: None,
            shodan: None,
            fofa: None,
            crtsh: CrtShClient::new()?,
            wayback: WaybackClient::new()?,
            ubuntu: UbuntuUsnClient::new()?,
            redhat: RedHatClient::new()?,
            debian: DebianClient::new()?,
            arch: ArchClient::new()?,
            github: None,
        })
    }

    /// Collect complete intelligence for a target domain.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn collect(&self, domain: &str) -> Result<TargetProfile> {
        info!("Starting intelligence collection for: {}", domain);

        // Check cache first
        let cache_key = format!("profile:{}", domain);
        if let Some(profile) = self.kb.get::<TargetProfile>(&cache_key)? {
            info!("Using cached profile for: {}", domain);
            return Ok(profile);
        }

        let mut profile = TargetProfile {
            domain: domain.to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(6),
            ..Default::default()
        };

        // Collect from all sources (sequentially for now to avoid lifetime issues)
        // Subdomains from crt.sh
        if let Err(e) = self.collect_subdomains(domain).await {
            error!("crt.sh collection failed: {}", e);
        }

        // Historic endpoints from Wayback
        if let Err(e) = self.collect_historic_endpoints(domain).await {
            error!("Wayback collection failed: {}", e);
        }

        // Shodan data (if configured)
        if self.shodan.is_some() {
            if let Err(e) = self.collect_shodan(domain).await {
                error!("Shodan collection failed: {}", e);
            }
        }

        // FOFA data (if configured)
        if self.fofa.is_some() {
            if let Err(e) = self.collect_fofa(domain).await {
                error!("FOFA collection failed: {}", e);
            }
        }

        // Build profile from collected data
        profile.subdomains = self.kb.get(&format!("subdomains:{}", domain))?.unwrap_or_default();
        profile.historic_endpoints = self
            .kb
            .get(&format!("endpoints:{}", domain))?
            .unwrap_or_default();
        profile.shodan_banners = self
            .kb
            .get(&format!("shodan:{}", domain))?
            .unwrap_or_default();

        // Detect tech stack from banners
        profile.tech_stack = self.detect_tech_stack(&profile);

        // Collect CVEs based on detected technologies
        profile.cves = self.collect_cves(&profile.tech_stack).await?;

        // Collect distro advisories based on OS
        profile.advisories = self.collect_advisories(&profile.tech_stack).await?;

        // Cache the complete profile
        self.kb.put_with_ttl(&cache_key, &profile, 6 * 3600)?;

        info!(
            "Collection complete for {}: {} subdomains, {} endpoints, {} CVEs",
            domain,
            profile.subdomains.len(),
            profile.historic_endpoints.len(),
            profile.cves.len()
        );

        Ok(profile)
    }

    /// Get cached context for a target (for validator use).
    pub async fn get_context_for_target(&self, target: &str) -> Result<TargetProfile> {
        // Extract domain from URL if needed
        let domain = target
            .replace("http://", "")
            .replace("https://", "")
            .split('/')
            .next()
            .unwrap_or(target)
            .to_string();

        self.collect(&domain).await
    }

    #[instrument(skip(self))]
    async fn collect_subdomains(&self, domain: &str) -> Result<()> {
        let permit = self.semaphore.clone().acquire_owned().await?;
        let _permit = permit; // Hold until end of scope

        let cache_key = format!("subdomains:{}", domain);

        // Check cache
        if self.kb.get::<Vec<String>>(&cache_key)?.is_some() {
            debug!("Subdomains cached for {}", domain);
            return Ok(());
        }

        match self.crtsh.get_subdomains(domain).await {
            Ok(subdomains) => {
                self.kb.put_with_ttl(&cache_key, &subdomains, CrtShClient::cache_ttl())?;
                debug!("Collected {} subdomains for {}", subdomains.len(), domain);
            }
            Err(e) => {
                warn!("crt.sh failed for {}: {}", domain, e);
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn collect_historic_endpoints(&self, domain: &str) -> Result<()> {
        let permit = self.semaphore.clone().acquire_owned().await?;
        let _permit = permit;

        let cache_key = format!("endpoints:{}", domain);

        if self.kb.get::<Vec<HistoricEndpoint>>(&cache_key)?.is_some() {
            debug!("Endpoints cached for {}", domain);
            return Ok(());
        }

        match self.wayback.get_urls(domain).await {
            Ok(endpoints) => {
                self.kb.put_with_ttl(&cache_key, &endpoints, WaybackClient::cache_ttl())?;
                debug!("Collected {} endpoints for {}", endpoints.len(), domain);
            }
            Err(e) => {
                warn!("Wayback failed for {}: {}", domain, e);
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn collect_shodan(&self, domain: &str) -> Result<()> {
        let Some(shodan) = &self.shodan else {
            return Ok(());
        };

        let permit = self.semaphore.clone().acquire_owned().await?;
        let _permit = permit;

        let cache_key = format!("shodan:{}", domain);

        if self.kb.get::<Vec<ShodanBanner>>(&cache_key)?.is_some() {
            return Ok(());
        }

        // Search by hostname
        let query = format!("hostname:{}", domain);
        match shodan.search(&query).await {
            Ok(hosts) => {
                let banners: Vec<ShodanBanner> = hosts
                    .into_iter()
                    .map(|h| ShodanBanner {
                        port: h.port,
                        banner: h.banner,
                        product: h.product,
                        version: h.version,
                    })
                    .collect();

                self.kb.put_with_ttl(&cache_key, &banners, ShodanClient::cache_ttl())?;
            }
            Err(e) => {
                warn!("Shodan failed: {}", e);
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn collect_fofa(&self, domain: &str) -> Result<()> {
        let Some(fofa) = &self.fofa else {
            return Ok(());
        };

        let permit = self.semaphore.clone().acquire_owned().await?;
        let _permit = permit;

        match fofa.search_domain(domain).await {
            Ok(results) => {
                debug!("FOFA found {} results", results.len());
                // Store FOFA results for tech stack detection
            }
            Err(e) => {
                warn!("FOFA failed: {}", e);
            }
        }

        Ok(())
    }

    fn detect_tech_stack(&self, profile: &TargetProfile) -> TechStack {
        let mut stack = TechStack::default();

        // Detect from Shodan banners
        for banner in &profile.shodan_banners {
            let b = banner.banner.to_lowercase();

            // Web server detection
            if b.contains("apache") {
                stack.server = banner.product.clone().unwrap_or_else(|| "Apache".to_string());
                if let Some(v) = &banner.version {
                    stack.server.push_str("/");
                    stack.server.push_str(v);
                }
            } else if b.contains("nginx") {
                stack.server = banner.product.clone().unwrap_or_else(|| "nginx".to_string());
                if let Some(v) = &banner.version {
                    stack.server.push_str("/");
                    stack.server.push_str(v);
                }
            }

            // Database detection from banners is hard, skip for now
        }

        // Default to MySQL if no DB detected
        if stack.db.is_empty() {
            stack.db = "MySQL".to_string();
        }

        stack
    }

    #[instrument(skip(self))]
    async fn collect_cves(&self, stack: &TechStack) -> Result<Vec<CveInfo>> {
        let Some(nvd) = &self.nvd else {
            return Ok(vec![]);
        };

        let mut all_cves = vec![];
        let mut seen = std::collections::HashSet::new();

        // Search by product keywords
        let keywords = extract_keywords(stack);
        for keyword in keywords.iter().take(3) {
            let cache_key = format!("cves:{}", keyword);

            let cves: Vec<CveInfo> = if let Some(cached) = self.kb.get(&cache_key)? {
                cached
            } else {
                match nvd.search_by_keyword(keyword).await {
                    Ok(cves) => {
                        let _ = self.kb.put_with_ttl(&cache_key, &cves, NvdClient::cache_ttl());
                        cves
                    }
                    Err(e) => {
                        warn!("NVD search failed for '{}': {}", keyword, e);
                        vec![]
                    }
                }
            };

            for cve in cves {
                if seen.insert(cve.cve_id.clone()) {
                    all_cves.push(cve);
                }
            }

            // Rate limiting
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // Sort by CVSS score
        all_cves.sort_by(|a, b| {
            b.cvss.unwrap_or(0.0)
                .partial_cmp(&a.cvss.unwrap_or(0.0))
                .unwrap()
        });

        Ok(all_cves.into_iter().take(50).collect())
    }

    #[instrument(skip(self))]
    async fn collect_advisories(&self, stack: &TechStack) -> Result<Vec<DistroAdvisory>> {
        let mut advisories = vec![];

        // Detect OS from stack
        let os_lower = stack.os.to_lowercase();

        if os_lower.contains("ubuntu") {
            // Try to extract release name
            let release = if os_lower.contains("22.04") || os_lower.contains("jammy") {
                "jammy"
            } else if os_lower.contains("20.04") || os_lower.contains("focal") {
                "focal"
            } else {
                "focal"
            };

            match self.ubuntu.get_advisories(release).await {
                Ok(mut usns) => {
                    advisories.append(&mut usns);
                }
                Err(e) => warn!("Ubuntu USN failed: {}", e),
            }
        }

        // Limit results
        Ok(advisories.into_iter().take(20).collect())
    }
}

fn extract_keywords(stack: &TechStack) -> Vec<String> {
    let mut keywords = vec![];

    if !stack.server.is_empty() {
        // Extract just the product name
        let server_kw = stack
            .server
            .split('/')
            .next()
            .unwrap_or(&stack.server)
            .to_string();
        keywords.push(server_kw);
    }

    if !stack.db.is_empty() {
        let db_kw = stack.db.split('/').next().unwrap_or(&stack.db).to_string();
        keywords.push(db_kw);
    }

    if !stack.os.is_empty() {
        keywords.push(stack.os.clone());
    }

    keywords
}
