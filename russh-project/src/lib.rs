//! Shared authentication helpers for the lab SSH client and server.
//!
//! Unix accounts and Gitea users are separate. This crate accepts the lab
//! password for the names `root` and `lab` so both daemons can be reached
//! before SSH user keys are provisioned. Public keys are optional and are
//! read from an OpenSSH `authorized_keys` file when one is present.

use std::path::Path;

use russh_keys::key::PublicKey;
use russh_keys::PublicKeyBase64;

pub const LAB_USERS: &[&str] = &["root", "lab"];

pub fn crate_version() -> &'static str {
    option_env!("RUSSH_CRATE_VERSION").unwrap_or("0.40.1")
}

pub fn password_accepted(user: &str, password: &str, expected: &str) -> bool {
    !expected.is_empty() && LAB_USERS.contains(&user) && password == expected
}

pub fn load_authorized_keys(path: &Path) -> anyhow::Result<Vec<PublicKey>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    Ok(parse_authorized_keys(&text))
}

pub fn parse_authorized_keys(text: &str) -> Vec<PublicKey> {
    let mut keys = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let token = match (parts.next(), parts.next()) {
            (Some(_algo), Some(material)) => material,
            (Some(material), None) => material,
            _ => continue,
        };
        if let Ok(key) = russh_keys::parse_public_key_base64(token) {
            keys.push(key);
        }
    }
    keys
}

pub fn authorized(user: &str, key: &PublicKey, keys: &[PublicKey]) -> bool {
    LAB_USERS.contains(&user) && keys.iter().any(|candidate| candidate == key)
}

pub fn format_public_key(key: &PublicKey) -> String {
    format!("{} {}", key.name(), key.public_key_base64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_matches_only_lab_users() {
        assert!(password_accepted("lab", "secret", "secret"));
        assert!(password_accepted("root", "secret", "secret"));
        assert!(!password_accepted("git", "secret", "secret"));
        assert!(!password_accepted("lab", "other", "secret"));
        assert!(!password_accepted("lab", "secret", ""));
    }

    #[test]
    fn authorized_keys_skips_comments_and_matches_material() {
        let pair = russh_keys::key::KeyPair::generate_ed25519().expect("ed25519");
        let public = pair.clone_public_key().expect("public");
        let text = format!("# comment\n\n{}\nnot-a-key\n", format_public_key(&public));
        let parsed = parse_authorized_keys(&text);
        assert_eq!(parsed.len(), 1);
        assert!(authorized("lab", &public, &parsed));
        assert!(!authorized("git", &public, &parsed));
        assert!(!authorized("lab", &public, &[]));
    }
}
