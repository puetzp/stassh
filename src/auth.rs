use crate::types::User;
use anyhow::Context;
use std::{env, fs, path::Path, process, str::FromStr};

/// This function reads the contents from the temporary file whose
/// path is taken from the environment variable `SSH_USER_AUTH`.
/// This file is created by OpenSSH when the `ExposeAuthInfo` option
/// is enabled and contains the SSH public key that was used to
/// authenticate the client.
/// The public key is extracted from the temporary file and passed
/// to a yq filter that searches the user database (another JSON file)
/// for a user that is identified by this key.
/// When no user can be found an errors is returned to the client.
/// Otherwise the user name and permissions are parsed and the user
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
    let pubkey = {
        let var = "SSH_USER_AUTH";

        let value =
            env::var(var).context(format!("failed to read environment variable `{}`", var))?;

        let content =
            fs::read_to_string(&value).context(format!("failed to read file `{}`", value))?;

        // Ensure the first part of the line matches the expected
        // authentication method, then take the next two parts
        // (the string identifying the key type and the key itself)
        // and discard the rest.
        content
            .lines()
            .next()
            .map(|line| line.split_whitespace().collect::<Vec<&str>>())
            .filter(|item| item.first().is_some_and(|i| *i == "publickey"))
            .and_then(|item| item.get(1..3).map(|slice| slice.join(" ")))
            .ok_or(anyhow::anyhow!("failed to determine user"))?
    };

    // TODO: Use halt_error or something similar to modify the exit code when more
    // than one result is produced. Also check the exit code in the code to
    // differentiate between yq usage or compile errors and the "business logic"
    // error of having more than one filter result.
    // Depending on the type of error, the user should get different messages and
    // `logger` should produce different error messages as well to pinpoint the
    // actual problem with user authentication.

    let user = {
        let error = format!("failed to determine user using public key `{}`", pubkey);

        // This yq invocation searches for an item whose `ssh_keys` contain the
        // SSH key from OpenSSH's `ExposeAuthInfo` file.
        // If found, it returns multiple lines of output:
        // * the user name
        // * followed by zero or more lines of permissions in the form
        //   <write> <path>
        //   where `write` is `true` or `false` to indicate if the user is
        //   permitted to write to the path.
        //
        // The `--exit-status` flag ensures that the program fails when the yq
        // filter does not yield any result, which means the user could not be
        // authenticated.
        let output = process::Command::new("yq")
            .arg("--raw-output")
            .arg("--exit-status")
            .arg(format!(
                "map_values(select(.ssh_keys[] | contains(\"{}\"))) as $match | if ($match | length == 1) then [($match | keys | first), ( $match | map(select(has(\"permissions\"))) | first | .permissions // {{}} | map(\"\\(.write // false) \\(.path)\") )] | flatten | join(\"\\n\") else false end",
                pubkey
            ))
            .arg(&users_file)
            .output()
            .context(error.clone())?;

        if !output.status.success() {
            let stderr = String::from_utf8(output.stderr)?;

            if !stderr.is_empty() {
                anyhow::bail!(anyhow::anyhow!(stderr).context(error.clone()))
            } else {
                anyhow::bail!(error)
            }
        } else {
            // Create the user object from the yq output described above.
            User::from_str(String::from_utf8(output.stdout)?.trim())?
        }
    };

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
        assert!(user.permissions[0].path == Path::new("/foo/bar"));
        assert!(user.permissions[0].write == false);
        assert!(user.permissions[1].path == Path::new("/bar/foo"));
        assert!(user.permissions[1].write == true);

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
