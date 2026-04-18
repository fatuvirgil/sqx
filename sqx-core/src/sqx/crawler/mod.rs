//! SQX Crawler — automatic injection-point discovery.
//!
//! Follows links and parses HTML forms to surface parameters that SQX
//! should test, so the user doesn't have to provide URLs manually.
//!
//! ## Crawler Types
//!
//! - [`Spider`] — Fast regex-based crawler for static HTML
//! - [`headless::HeadlessCrawler`] — Chrome-based crawler for SPAs and JS-heavy apps

pub mod models;
pub mod spider;

pub use models::{
    CrawlResult, CrawlerConfig, DiscoveredParam, HttpMethod, InjectionPoint, ParamLocation,
};
pub use spider::Spider;

// Note: Headless crawler moved to sqx-pro
// pub mod headless;
// pub use headless::{
//     ApiEndpoint, ApiSource, HeadlessBrowser, HeadlessConfig, HeadlessCrawler, HeadlessCrawlResult,
//     is_chrome_available, find_chrome_binary,
// };
