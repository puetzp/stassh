use crate::types::{PrefixedPath, User};
use anyhow::Context;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};

/// Create a new secret using `systemd-creds`. This function will fail
/// when the secret already exists. Standard input is inherited from the
/// parent process, so `systemd-creds` can read the secret straight from
/// the user's ssh client.
pub fn create(data_dir: &PathBuf, user: &User, path: &PrefixedPath) -> Result<(), anyhow::Error> {
    if !user.can_write(path) {
        anyhow::bail!("permission denied")
    }

    let real_path = path.prepend(user, data_dir)?;

    if real_path
        .try_exists()
        .context("failed to check if secret exists")?
    {
        anyhow::bail!("secret already exists")
    }

    if let Some(parent) = real_path.parent() {
        fs::create_dir_all(parent).context("failed to create parent directory")?;
    }

    let output = Command::new("systemd-creds")
        .arg("--user")
        .arg("encrypt")
        .arg("-")
        .arg(&real_path)
        .stdin(Stdio::inherit())
        .output()
        .context("failed to create secret")?;

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr)?;

        if !stderr.is_empty() {
            anyhow::bail!(anyhow::anyhow!(stderr).context("failed to create secret"))
        } else {
            anyhow::bail!("failed to create secret")
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
        anyhow::bail!("permission denied")
    }

    let real_path = path.prepend(user, data_dir)?;

    if !create
        && !real_path
            .try_exists()
            .context("failed to check if secret exists")?
    {
        anyhow::bail!("no such secret")
    }

    if let Some(parent) = real_path.parent() {
        fs::create_dir_all(parent).context("failed to create parent directory")?;
    }

    let output = Command::new("systemd-creds")
        .arg("--user")
        .arg("encrypt")
        .arg("-")
        .arg(&real_path)
        .stdin(Stdio::inherit())
        .output()
        .context("failed to create secret")?;

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr)?;

        if !stderr.is_empty() {
            anyhow::bail!(anyhow::anyhow!(stderr).context("failed to create secret"))
        } else {
            anyhow::bail!("failed to create secret")
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
        anyhow::bail!("permission denied")
    }

    let real_path = path.prepend(user, data_dir)?;

    if !real_path
        .try_exists()
        .context("failed to check if secret exists")?
    {
        anyhow::bail!("no such secret")
    }

    if real_path.is_file() {
        fs::remove_file(&real_path).context("failed to delete secret")?;
    } else if real_path.is_dir() {
        if force {
            fs::remove_dir_all(&real_path).context("failed to delete directory")?;
        } else {
            let count = fs::read_dir(&real_path)
                .context("failed to stat directory")?
                .filter_map(|entry| entry.ok())
                .count();

            if count > 0 {
                anyhow::bail!("failed to delete non-empty directory, use --force to force removal or delete secrets first");
            } else {
                fs::remove_dir(&real_path).context("failed to delete directory")?;
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
        anyhow::bail!("permission denied")
    }

    let real_path = path.prepend(user, data_dir)?;

    if !real_path
        .try_exists()
        .context("failed to check if secret exists")?
    {
        anyhow::bail!("no such secret")
    }

    let output = Command::new("systemd-creds")
        .arg("--user")
        .arg("decrypt")
        .arg(&real_path)
        .arg("-")
        .output()
        .context("failed to create secret")?;

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr)?;

        if !stderr.is_empty() {
            anyhow::bail!(anyhow::anyhow!(stderr).context("failed to create secret"))
        } else {
            anyhow::bail!("failed to create secret")
        }
    } else {
        let stdout = String::from_utf8(output.stdout)?;

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
        anyhow::bail!("permission denied")
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
                    .context("failed to stat directory")?
                    .filter_map(|entry| entry.ok())
                {
                    *item = entry.path();
                    recurse(real_path_count, prefixed_path, paths, item)?;
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

    recurse(real_path_count, &path, &mut paths, &mut item)?;

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
