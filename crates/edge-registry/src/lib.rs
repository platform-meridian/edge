//! A power-cut-safe OCI image store, and the registry that serves it: read
//! by anyone on the host, written by the identities its [`push::Authority`]
//! names.

mod digest;
mod import;
mod manifest;
pub mod push;
mod reference;
mod server;
mod store;
mod sweep;

pub use digest::Digest;
pub use reference::ImageRef;
pub use server::{serve, serve_waiting};
pub use store::{Listing, Store};
pub use sweep::Swept;
