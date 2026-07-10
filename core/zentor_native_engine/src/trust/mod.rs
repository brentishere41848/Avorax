pub mod allowlist;
pub mod false_positive_store;
pub mod known_bad;
pub mod known_good;
pub mod microsoft_trust;
pub mod publisher_trust;
mod store_io;
pub mod user_approvals;
pub mod zentor_trust;

pub use allowlist::Allowlist;
pub use known_bad::KnownBadStore;
pub use known_good::KnownGoodStore;

#[cfg(test)]
mod tests {
    #[test]
    fn native_trust_does_not_export_dead_publisher_stub() {
        let source = include_str!("mod.rs");
        let dead_export = ["pub mod trusted_", "publishers;"].concat();

        assert!(!source.contains(&dead_export));
    }
}
