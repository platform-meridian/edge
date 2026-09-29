//! A power-cut-safe OCI image store, and the read-only registry that serves it.

mod digest;
mod import;
mod manifest;
mod reference;
mod store;
mod sweep;

pub use digest::Digest;
pub use reference::{ImageRef, normalize_repo};
pub use store::{Listing, Store};
pub use sweep::Swept;
