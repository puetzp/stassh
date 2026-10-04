use crate::{
    error,
    types::{PrefixedPath, User},
};
use anyhow::Context;
use std::{
    fs, io,
    path::PathBuf,
    process::{Command, Stdio},
};

/// Create a new secret using `systemd-creds`. This function will fail
/// when the secret already exists. Standard input is inherited from the
/// parent process, so `systemd-creds` can read the secret straight from
/// the user's ssh client.
pub fn create(data_dir: &PathBuf, user: &User, path: &PrefixedPath) -> Result<(), anyhow::Error> {
    if !user.can_write(path) {
        anyhow::bail!(error::UserError::new("permission denied".to_string()))
    }

    if path.is_root() {
        anyhow::bail!(error::UserError::new(format!(
            "cannot create secret `{}` because it matches the path of the root directory",
            path
        )));
    }

    let real_path = path.prepend(user, data_dir)?;

    match fs::metadata(&real_path) {
        Ok(metadata) => {
            if metadata.is_dir() {
                anyhow::bail!(error::UserError::new(format!(
                    "cannot create secret `{}` because the same path already refers to a directory ",
                    path
                )));
            } else {
                anyhow::bail!(error::UserError::new(format!(
                    "secret `{}` already exists",
                    path
                )));
            }
        }
        Err(error) => {
            if error.kind() != io::ErrorKind::NotFound {
                anyhow::bail!(anyhow::anyhow!(error).context(format!(
                    "failed to query metadata about path `{}`",
                    real_path.display()
                )));
            }
        }
    }

    if let Some(parent) = real_path.parent() {
        if !real_path.try_exists().context(format!(
            "failed to check if parent directory `{}` for secret `{}` exists",
            parent.display(),
            real_path.display()
        ))? {
            fs::create_dir_all(parent).context(format!(
                "failed to create parent directory `{}` for secret `{}`",
                parent.display(),
                real_path.display()
            ))?;
        }
    }

    let mut cmd = Command::new("systemd-creds");
    cmd.arg("--user");
    cmd.arg("encrypt");
    cmd.arg("-");
    cmd.arg(&real_path);
    cmd.stdin(Stdio::inherit());

    let output = cmd
        .output()
        .context(format!("failed to execute command `{:?}`", cmd))?;

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).context(format!(
            "failed to parse error output from command `{:?}` as utf-8",
            cmd
        ))?;

        if !stderr.is_empty() {
            anyhow::bail!(
                anyhow::anyhow!(stderr).context(format!("command `{:?}` returned an error", cmd))
            );
        } else {
            anyhow::bail!("command `{:?}` failed but returned no error message", cmd);
        }
    }

    Ok(())
}

/// Update an existing secret. Works the same as `create`, however an
/// existing secret is not overwritten by default. An additional flag
/// makes the function idempotent, if requested so by the user.
pub fn update(
    data_dir: &PathBuf,
    user: &User,
    path: &PrefixedPath,
    create: bool,
) -> Result<(), anyhow::Error> {
    if !user.can_write(path) {
        anyhow::bail!(error::UserError::new("permission denied".to_string()))
    }

    let real_path = path.prepend(user, data_dir)?;

    match fs::metadata(&real_path) {
        Ok(metadata) => {
            if create && metadata.is_dir() {
                anyhow::bail!(error::UserError::new(format!(
                    "cannot create secret `{}` because the same path already refers to a directory",
                    path
                )));
            }

            if metadata.is_dir() {
                anyhow::bail!(error::UserError::new(format!(
                    "cannot update secret `{}` because this path refers to a directory instead of a file",
                    path
                )))
            }
        }
        Err(error) => {
            if error.kind() == io::ErrorKind::NotFound {
                anyhow::bail!(error::UserError::new(format!(
                    "failed to update nonexistent secret `{}`; use `--create` wih `update` to create it first or use the `create` subcommand instead",
                    path
        )));
            } else {
                anyhow::bail!(anyhow::anyhow!(error).context(format!(
                    "failed to query metadata about path `{}`",
                    real_path.display()
                )));
            }
        }
    }

    if let Some(parent) = real_path.parent() {
        if !real_path.try_exists().context(format!(
            "failed to check if parent directory `{}` for secret `{}` exists",
            parent.display(),
            real_path.display()
        ))? {
            fs::create_dir_all(parent).context(format!(
                "failed to create parent directory `{}` for secret `{}`",
                parent.display(),
                real_path.display()
            ))?;
        }
    }

    let mut cmd = Command::new("systemd-creds");
    cmd.arg("--user");
    cmd.arg("encrypt");
    cmd.arg("-");
    cmd.arg(&real_path);
    cmd.stdin(Stdio::inherit());

    let output = cmd
        .output()
        .context(format!("failed to execute command `{:?}`", cmd))?;

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).context(format!(
            "failed to parse error output from command `{:?}` as utf-8",
            cmd
        ))?;

        if !stderr.is_empty() {
            anyhow::bail!(
                anyhow::anyhow!(stderr).context(format!("command `{:?}` returned an error", cmd))
            );
        } else {
            anyhow::bail!("command `{:?}` failed but returned no error message", cmd);
        }
    }

    Ok(())
}

/// This function deletes a secret or even a whole folder of secrets.
/// Non-empty folders/directories are not removed unless requested so
/// by the user via an additional flag.
pub fn delete(
    data_dir: &PathBuf,
    user: &User,
    path: &PrefixedPath,
    force: bool,
) -> Result<(), anyhow::Error> {
    if !user.can_write(path) {
        anyhow::bail!(error::UserError::new("permission denied".to_string()))
    }

    let real_path = path.prepend(user, data_dir)?;

    if !real_path.try_exists().context(format!(
        "failed to check if secret exists at `{}`",
        real_path.display()
    ))? {
        anyhow::bail!(error::UserError::new(format!(
            "cannot delete nonexistent secret or directory `{}`",
            path
        )));
    }

    if real_path.is_file() {
        fs::remove_file(&real_path)
            .context(format!("failed to delete file `{}`", real_path.display()))?;
    } else if real_path.is_dir() {
        if force {
            fs::remove_dir_all(&real_path).context(format!(
                "failed to delete directory `{}`",
                real_path.display()
            ))?;
        } else {
            let count = fs::read_dir(&real_path)
                .context(format!(
                    "failed to read entries in directory `{}`",
                    real_path.display()
                ))?
                .filter_map(|entry| entry.ok())
                .count();

            if count > 0 {
                anyhow::bail!(error::UserError::new(format!("failed to delete non-empty directory `{}`, use --force to force removal or delete secrets first", path)));
            } else {
                fs::remove_dir(&real_path).context(format!(
                    "failed to delete directory `{}`",
                    real_path.display()
                ))?;
            }
        }
    }

    Ok(())
}

/// This function returns a secret in decrypted form. An additional flag
/// is used to discard the trailing newline, which is useful in scripts
/// or automated processes such as CI/CD pipelines.
pub fn get(
    data_dir: &PathBuf,
    user: &User,
    path: &PrefixedPath,
    trim: bool,
) -> Result<(), anyhow::Error> {
    if !user.can_read(path) {
        anyhow::bail!(error::UserError::new("permission denied".to_string()))
    }

    let real_path = path.prepend(user, data_dir)?;

    if !real_path.try_exists().context(format!(
        "failed to check if secret exists at `{}`",
        real_path.display()
    ))? {
        anyhow::bail!(error::UserError::new(format!(
            "failed to find secret `{}`",
            path
        )));
    }

    let mut cmd = Command::new("systemd-creds");
    cmd.arg("--user");
    cmd.arg("decrypt");
    cmd.arg(&real_path);
    cmd.arg("-");

    let output = cmd
        .output()
        .context(format!("failed to execute command `{:?}`", cmd))?;

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).context(format!(
            "failed to parse error output from command `{:?}` as utf-8",
            cmd
        ))?;

        if !stderr.is_empty() {
            anyhow::bail!(
                anyhow::anyhow!(stderr).context(format!("command `{:?}` returned an error", cmd))
            );
        } else {
            anyhow::bail!("command `{:?}` failed but returned no error message", cmd);
        }
    } else {
        let stdout = String::from_utf8(output.stdout).context(format!(
            "failed to parse standard output from command `{:?}` as utf-8",
            cmd
        ))?;

        if trim {
            print!("{}", stdout);
        } else {
            println!("{}", stdout);
        }
    }

    Ok(())
}

/// List available secrets and folders. Folders will be displayed with a
/// trailing slash to appear more distinct from secrets (files).
///
/// The list of paths is determined recursively. It starts from the user-
/// supplied prefixed path (such as `pub:/my-team`) and descends into
/// every directory to build the list of paths. Every directory and file
/// on the way are added to the list. Meanwhile each real path (filesystem)
/// is translated to a prefixed path, by adding the difference of path
/// components between the starting path and current path to a copy of
/// the prefixed path supplied by the user.
pub fn list(data_dir: &PathBuf, user: &User, path: &PrefixedPath) -> Result<(), anyhow::Error> {
    if !user.can_read(path) {
        anyhow::bail!(error::UserError::new("permission denied".to_string()))
    }

    let real_path = path.prepend(user, data_dir)?;
    let real_path_count = real_path.components().count();

    let mut paths = vec![];
    let mut item = real_path.clone();

    fn recurse(
        real_path_count: usize,
        prefixed_path: &PrefixedPath,
        paths: &mut Vec<PrefixedPath>,
        item: &mut PathBuf,
    ) -> Result<(), anyhow::Error> {
        if item.exists() {
            if item.is_dir() {
                let mut _path = prefixed_path.clone();

                for component in item
                    .components()
                    .skip(real_path_count)
                    .map(|component| component.as_os_str())
                {
                    _path.push(component);
                }

                _path.set_trailing_sep();

                paths.push(_path);

                for entry in fs::read_dir(&item)
                    .context(format!(
                        "failed to read entries in directory `{}`",
                        item.display()
                    ))?
                    .filter_map(|entry| entry.ok())
                {
                    *item = entry.path();
                    recurse(real_path_count, prefixed_path, paths, item).context(format!(
                        "failed to parse paths in `{}` and add them to the output list",
                        item.display()
                    ))?;
                }
            } else {
                let mut _path = prefixed_path.clone();

                for component in item
                    .components()
                    .skip(real_path_count)
                    .map(|component| component.as_os_str())
                {
                    _path.push(component);
                }

                paths.push(_path);
            }
        }

        Ok(())
    }

    recurse(real_path_count, &path, &mut paths, &mut item).context(format!(
        "failed to parse paths in `{}` and add them to the output list",
        item.display()
    ))?;

    for path in paths {
        println!("{}", path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // TODO: Figure out a way to unit-test the functions in this module.
    //       Have not found a decent way of passing stdin to the calls to
    //       `systemd-creds` yet.
}
