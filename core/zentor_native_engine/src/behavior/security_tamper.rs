pub fn security_tamper_score(command_line: &str) -> u32 {
    let lower = command_line.to_ascii_lowercase();
    [
        "set-mppreference",
        "disableantispyware",
        "vssadmin delete shadows",
        "wbadmin delete catalog",
        "bcdedit /set recoveryenabled no",
    ]
    .iter()
    .map(|term| lower.matches(term).count() as u32 * 25)
    .sum()
}
