//! guard_core — the guard binary's scan engine core: rule matching and
//! content heuristics, YARA rules compiled and matched by yara-x (`yara.rs`;
//! the JSON rule format stays as a compatibility layer alongside them), and
//! native file-change events for the watcher (`watch.rs`).

pub mod entropy;
pub mod heuristics;
pub mod rules;
pub mod watch;
pub mod yara;
