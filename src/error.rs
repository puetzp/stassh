use std::fmt;

#[derive(Debug)]
pub struct AuthenticationError {
    pubkey: Option<String>,
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.pubkey {
            Some(pubkey) => write!(
                f,
                "failed to authenticate user using SSH public key `{}`",
                pubkey
            ),
            None => f.write_str("failed to authenticate user"),
        }
    }
}

impl AuthenticationError {
    pub fn new(pubkey: Option<&str>) -> Self {
        Self {
            pubkey: pubkey.map(|s| s.to_string()),
        }
    }
}

#[derive(Debug)]
pub struct UserError {
    message: String,
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
