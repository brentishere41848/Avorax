pub fn credential_access_score(browser_reads: u32, wallet_reads: u32) -> u32 {
    browser_reads.saturating_mul(15) + wallet_reads.saturating_mul(25)
}
