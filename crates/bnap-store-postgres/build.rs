//! Rebuilds the crate when a migration changes: `sqlx::migrate!` embeds
//! them at compile time.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
