pub fn credential_access_score(browser_reads: u32, wallet_reads: u32) -> u32 {
    browser_reads
        .saturating_mul(15)
        .saturating_add(wallet_reads.saturating_mul(25))
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_behavior_disabled_credential_score_saturates() {
        assert_eq!(super::credential_access_score(u32::MAX, u32::MAX), u32::MAX);
    }
}
