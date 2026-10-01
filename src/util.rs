use anyhow::Context;

/// Use the `mktemp` utility to create a temporary file or
/// directory in `/tmp`.
/// This is mostly useful in tests.
pub fn tempfile(directory: bool) -> Result<std::path::PathBuf, anyhow::Error> {
    let mut command = std::process::Command::new("mktemp");

    if directory {
        command.arg("--directory");
    }

    let output = command
        .output()
        .context("failed to create temporary file")?;

    let path = if !output.status.success() {
        anyhow::bail!("failed to create temporary file");
    } else {
        std::path::PathBuf::from(String::from_utf8(output.stdout)?.trim())
    };

    Ok(path)
}
