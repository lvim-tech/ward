//! ward — a pinentry that asks and never keeps.
//!
//! The binary is a thin shell around this library. The split is not ceremony: an
//! integration test cannot reach inside a `bin` crate, and the parts most worth testing —
//! the percent codec, the locked buffer's character counting, the command dispatch — are
//! exactly the parts that would otherwise only be exercised by running the whole program
//! against a live gpg-agent, which is the one thing this project must not do casually.

pub mod assuan;
pub mod harden;
pub mod install;
pub mod secret;
pub mod server;
pub mod theme;
pub mod ui;
