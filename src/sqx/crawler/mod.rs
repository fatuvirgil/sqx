//! SQX Crawler — automatic injection-point discovery.
//!
//! Follows links and parses HTML forms to surface parameters that SQX
//! should test, so the user doesn't have to provide URLs manually.

pub mod models;
pub mod spider;

pub use models::{
    CrawlerConfig, DiscoveredParam, HttpMethod, InjectionPoint, ParamLocation,
};
pub use spider::Spider;
