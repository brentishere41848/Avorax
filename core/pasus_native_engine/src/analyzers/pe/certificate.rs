pub fn signature_presence_status(certificate_table_present: bool) -> &'static str {
    if certificate_table_present {
        "signature-indicator-present"
    } else {
        "signature-not-parsed"
    }
}
