use crate::{
    error::AuthenticationError,
    types::{User, UserAttributes, Username},
};
use anyhow::Context;
use std::{collections::HashMap, env, fs, path::Path};

/// This function reads the contents from the temporary file whose
/// path is taken from the environment variable `SSH_USER_AUTH`.
/// This file is created by OpenSSH when the `ExposeAuthInfo` option
/// is enabled and contains the SSH public key that was used to
/// authenticate the client.
///
/// The public key is extracted from the temporary file and compared
/// with all users and their respective public keys in the user database
/// (another JSON file) to find the user that is identified by this key.
/// When no user can be found an errors is returned to the client.
/// Otherwise the user name and permissions are retainedd and the user
/// object is returned to the caller to continue processing the user's input.
///
/// Note that for this workflow to function properly, the user database
/// and authorized_keys file that is taken into account by OpenSSH need
/// to be synchronized. However this bit of configuration is considered
/// to be outside of the scope of this project since it falls firmly into
/// configuration management territory.
///
/// To that end a key that is missing in the authorized_keys file will
/// simply lead to failing SSH client and server authentication, while a key
/// that is missing from the user database results in a error message to the
/// client that the user could not be identified.
pub fn authenticate(users_file: &Path) -> Result<User, anyhow::Error> {
    fn extract_pubkey() -> Result<String, anyhow::Error> {
        let var = "SSH_USER_AUTH";

        let file_path =
            env::var(var).context(format!("failed to read environment variable `{}`", var))?;

        let file_content = fs::read_to_string(&file_path)
            .context(format!("failed to read file `{}`", file_path))?;

        // Ensure the first part of the line matches the expected
        // authentication method, then take the next two parts
        // (the string identifying the key type and the key itself)
        // and discard the rest.
        let pubkey = file_content
            .lines()
            .next()
            .map(|line| line.split_whitespace().collect::<Vec<&str>>())
            .filter(|item| item.first().is_some_and(|i| *i == "publickey"))
            .and_then(|item| item.get(1..3).map(|slice| slice.join(" ")))
            .ok_or(anyhow::anyhow!(
                "failed to extract SSH public key from file `{}`",
                file_path
            ))?;

        Ok(pubkey)
    }

    let pubkey = extract_pubkey().context(AuthenticationError::new(None))?;

    fn determine_user(users_file: &Path, pubkey: &str) -> Result<User, anyhow::Error> {
        let file_content = fs::read_to_string(&users_file).context(format!(
            "failed to read user configuration from file `{}`",
            users_file.display()
        ))?;

        type Users = HashMap<Username, UserAttributes>;

        // Parse the complete file and all contained user entries, then
        // filter the set of users and retain only those whose set of
        // public keys matches the public key parsed from `SSH_USER_AUTH`.
        let users: Users = strict_yaml_rust::serde::de::from_str::<Users>(&file_content)
            .context(format!(
                "failed to parse user configuration from file `{}`",
                users_file.display()
            ))?
            .into_iter()
            .filter(|(_, attributes)| attributes.ssh_keys.iter().any(|key| key.as_str() == pubkey))
            .collect();

        // Ensure at most one user is identified by the public key.
        if users.len() > 1 {
            anyhow::bail!("SSH public key `{}` is used by multiple users, but a key must identify a single user unambiguously", pubkey);
        }

        let user = users
            .into_iter()
            .last()
            .map(|(name, attributes)| User { name, attributes })
            .ok_or(anyhow::anyhow!(
                "failed to find any user identified by SSH public key `{}`",
                pubkey
            ))?;

        Ok(user)
    }

    let user =
        determine_user(users_file, &pubkey).context(AuthenticationError::new(Some(&pubkey)))?;

    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticate_success() -> Result<(), anyhow::Error> {
        let ssh_auth_sock_file = {
            let path = crate::util::tempfile(false)?;

            unsafe {
                env::set_var("SSH_USER_AUTH", &path);
            }

            fs::write(&path, "publickey ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOanWI/5F1kXlk2Om/bIoozTOTEVLYKgj+WxlY5phee1\n")?;

            path
        };

        let users_file = {
            let path = crate::util::tempfile(false)?;

            fs::write(
                &path,
                r#"
me:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U
other:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4OaADJGliETiTzt0npH2aky62s4XLgpern6d4D1/Sh
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOanWI/5F1kXlk2Om/bIoozTOTEVLYKgj+WxlY5phee1
  permissions:
    - path: /foo/bar
    - path: /bar/foo
      write: true
"#,
            )?;

            path
        };

        let user = authenticate(&users_file);

        fs::remove_file(&ssh_auth_sock_file)?;
        fs::remove_file(&users_file)?;

        let user = user?;

        assert!(user.name.as_str() == "other");
        assert!(user.attributes.permissions[0].path == Path::new("/foo/bar"));
        assert!(user.attributes.permissions[0].write == false);
        assert!(user.attributes.permissions[1].path == Path::new("/bar/foo"));
        assert!(user.attributes.permissions[1].write == true);

        Ok(())
    }

    #[test]
    fn test_authenticate_failure() -> Result<(), anyhow::Error> {
        let ssh_auth_sock_file = {
            let path = crate::util::tempfile(false)?;

            unsafe {
                env::set_var("SSH_USER_AUTH", &path);
            }

            fs::write(&path, "publickey ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOanWI/5F1kXlk2Om/bIoozTOTEVLYKgj+WxlY5phee1\n")?;

            path
        };

        let users_file = {
            let path = crate::util::tempfile(false)?;

            fs::write(
                &path,
                r#"
me:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOanWI/5F1kXlk2Om/bIoozTOTEVLYKgj+WxlY5phee1
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U
other:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4OaADJGliETiTzt0npH2aky62s4XLgpern6d4D1/Sh
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOanWI/5F1kXlk2Om/bIoozTOTEVLYKgj+WxlY5phee1
"#,
            )?;

            path
        };

        let user = authenticate(&users_file);

        fs::remove_file(&ssh_auth_sock_file)?;
        fs::remove_file(&users_file)?;

        assert!(user.is_err());

        Ok(())
    }
}
