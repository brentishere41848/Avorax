use anyhow::Result;
use ed25519_dalek::SigningKey;

fn main() -> Result<()> {
    match parse_generate_update_key_args(std::env::args().skip(1))? {
        GenerateKeyAction::Generate => generate_update_key(),
        GenerateKeyAction::Help => {
            print_usage();
            Ok(())
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum GenerateKeyAction {
    Generate,
    Help,
}

fn parse_generate_update_key_args(
    args: impl IntoIterator<Item = String>,
) -> Result<GenerateKeyAction> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(GenerateKeyAction::Generate);
    };
    if first == "--help" || first == "-h" {
        anyhow::ensure!(
            args.next().is_none(),
            "unexpected extra update key generator arguments"
        );
        return Ok(GenerateKeyAction::Help);
    }
    anyhow::bail!("unexpected update key generator argument: {first}");
}

fn print_usage() {
    eprintln!("Usage: avorax_generate_update_key [--help]");
    eprintln!(
        "Generates an Ed25519 update signing seed and public key on stdout; run only in a protected signing environment."
    );
}

fn generate_update_key() -> Result<()> {
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|error| anyhow::anyhow!("failed to generate update key: {error}"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    println!("private={}", hex::encode(seed));
    println!("public={}", hex::encode(verifying_key.to_bytes()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_generate_update_key_args, GenerateKeyAction};

    #[test]
    fn update_key_generator_defaults_to_generate() {
        assert_eq!(
            parse_generate_update_key_args(Vec::<String>::new()).unwrap(),
            GenerateKeyAction::Generate
        );
    }

    #[test]
    fn update_key_generator_help_does_not_generate_key_material() {
        assert_eq!(
            parse_generate_update_key_args(vec!["--help".to_string()]).unwrap(),
            GenerateKeyAction::Help
        );
        assert_eq!(
            parse_generate_update_key_args(vec!["-h".to_string()]).unwrap(),
            GenerateKeyAction::Help
        );
    }

    #[test]
    fn update_key_generator_rejects_unexpected_arguments() {
        let error = parse_generate_update_key_args(vec!["output.txt".to_string()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("unexpected update key generator argument"));
    }

    #[test]
    fn update_key_generator_help_rejects_trailing_arguments() {
        let error = parse_generate_update_key_args(vec!["--help".to_string(), "extra".to_string()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("unexpected extra update key generator arguments"));
    }
}
