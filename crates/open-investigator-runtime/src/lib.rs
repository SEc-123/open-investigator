//! Open Investigator runtime.
//!
//! Runtime for Open Investigator.
//!
//! This crate contains the only runtime needed by the product: case management,
//! evidence storage, read-only command policy, host collectors, AI function-tool loop,
//! and report generation for local server incident investigation.

pub mod agent;
pub mod analyst;
pub mod case;
pub mod collector;
pub mod config;
pub mod model;
pub mod playbook;
pub mod policy;
pub mod report;
pub mod runner;
pub mod store;
pub mod tools;
pub mod util;

pub use case::CaseContext;
pub use config::OiConfig;
pub use model::InvestigationMode;
pub use playbook::InvestigationEngine;
pub use policy::ReadonlyPolicy;
pub use runner::CommandRunner;
pub use store::EvidenceStore;
