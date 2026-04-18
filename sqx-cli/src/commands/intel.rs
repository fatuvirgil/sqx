use sqx_core::intel::{IntelCollector, TargetProfile};

pub async fn run_intel(
    domain: String,
    output: String,
    out_file: Option<String>,
    kb_path: String,
) {
    eprintln!("[*] Collecting intelligence for: {}", domain);
    
    let collector = match IntelCollector::new(&kb_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Failed to create intel collector: {}", e);
            return;
        }
    };
    
    match collector.collect(&domain).await {
        Ok(profile) => {
            let result = format_intel_result(&profile, &output);
            
            if let Some(path) = out_file {
                match std::fs::write(&path, &result) {
                    Ok(()) => eprintln!("[+] Intelligence written to: {}", path),
                    Err(e) => eprintln!("[-] Failed to write output: {}", e),
                }
            } else {
                println!("{}", result);
            }
        }
        Err(e) => {
            eprintln!("[-] Intelligence collection failed: {}", e);
        }
    }
}

fn format_intel_result(profile: &TargetProfile, format: &str) -> String {
    match format {
        "json" => match serde_json::to_string_pretty(profile) {
            Ok(json) => json,
            Err(e) => format!("[-] JSON serialization failed: {}", e),
        },
        _ => format_intel_text(profile),
    }
}

fn format_intel_text(profile: &TargetProfile) -> String {
    let mut out = String::new();
    
    out.push_str(&format!("╔═══════════════════════════════════════════════════════════════╗\n"));
    out.push_str(&format!("║            INTELLIGENCE PROFILE: {:30} ║\n", profile.domain));
    out.push_str(&format!("╚═══════════════════════════════════════════════════════════════╝\n\n"));
    
    // IP Address
    if let Some(ref ip) = profile.ip {
        out.push_str(&format!("[IP Address] {}\n\n", ip));
    }
    
    // CVEs
    out.push_str("[CVEs]\n");
    if profile.cves.is_empty() {
        out.push_str("  No CVEs found\n");
    } else {
        for cve in &profile.cves {
            let cvss_str = cve.cvss.map(|s| format!("CVSS {:.1}", s)).unwrap_or_else(|| "N/A".to_string());
            out.push_str(&format!("  • {} ({}): Product: {}\n", 
                cve.cve_id, 
                cvss_str,
                cve.affected_product
            ));
            if cve.exploit_available {
                out.push_str("    ⚠ Exploit available\n");
            }
        }
    }
    
    // Technology Stack
    out.push_str("\n[Technology Stack]\n");
    let ts = &profile.tech_stack;
    if ts.server.is_empty() && ts.db.is_empty() && ts.os.is_empty() && ts.runtime.is_empty() {
        out.push_str("  No tech stack identified\n");
    } else {
        if !ts.server.is_empty() {
            out.push_str(&format!("  Server: {}\n", ts.server));
        }
        if !ts.db.is_empty() {
            out.push_str(&format!("  Database: {}\n", ts.db));
        }
        if !ts.os.is_empty() {
            out.push_str(&format!("  OS: {}\n", ts.os));
        }
        if !ts.runtime.is_empty() {
            out.push_str(&format!("  Runtime: {}\n", ts.runtime));
        }
        if !ts.framework.is_empty() {
            out.push_str(&format!("  Framework: {}\n", ts.framework));
        }
        if !ts.extra.is_empty() {
            out.push_str(&format!("  Extra: {:?}\n", ts.extra));
        }
    }
    
    // Historic Endpoints
    out.push_str("\n[Historic Endpoints]\n");
    if profile.historic_endpoints.is_empty() {
        out.push_str("  No historic endpoints discovered\n");
    } else {
        for ep in profile.historic_endpoints.iter().take(20) {
            let params = if ep.parameters.is_empty() {
                "".to_string()
            } else {
                format!(" [{}]", ep.parameters.join(", "))
            };
            out.push_str(&format!("  • {}{} (from {})\n", ep.url, params, ep.source));
        }
        if profile.historic_endpoints.len() > 20 {
            out.push_str(&format!("  ... and {} more\n", profile.historic_endpoints.len() - 20));
        }
    }
    
    // Subdomains
    out.push_str("\n[Subdomains]\n");
    if profile.subdomains.is_empty() {
        out.push_str("  No subdomains found\n");
    } else {
        for sd in profile.subdomains.iter().take(20) {
            out.push_str(&format!("  • {}\n", sd));
        }
        if profile.subdomains.len() > 20 {
            out.push_str(&format!("  ... and {} more\n", profile.subdomains.len() - 20));
        }
    }
    
    // Shodan Banners
    out.push_str("\n[Shodan Banners]\n");
    if profile.shodan_banners.is_empty() {
        out.push_str("  No Shodan data\n");
    } else {
        for banner in profile.shodan_banners.iter().take(10) {
            let product = banner.product.as_deref().unwrap_or("Unknown");
            out.push_str(&format!("  • Port {}: {}\n", banner.port, product));
        }
        if profile.shodan_banners.len() > 10 {
            out.push_str(&format!("  ... and {} more\n", profile.shodan_banners.len() - 10));
        }
    }
    
    // Advisories
    out.push_str("\n[Security Advisories]\n");
    if profile.advisories.is_empty() {
        out.push_str("  No advisories found\n");
    } else {
        for adv in profile.advisories.iter().take(10) {
            out.push_str(&format!("  • [{}] {} - {} (Severity: {})\n", 
                adv.distro, adv.advisory_id, adv.package, adv.severity));
        }
        if profile.advisories.len() > 10 {
            out.push_str(&format!("  ... and {} more\n", profile.advisories.len() - 10));
        }
    }
    
    // Metadata
    out.push_str(&format!("\n[Metadata]\n"));
    out.push_str(&format!("  Created: {}\n", profile.created_at.format("%Y-%m-%d %H:%M:%S UTC")));
    out.push_str(&format!("  Expires: {}\n", profile.expires_at.format("%Y-%m-%d %H:%M:%S UTC")));
    
    out
}
