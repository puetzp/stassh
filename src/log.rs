//! In normal circumstances it would be great to just use crates
//! such as `env_logger` to log messages. However this is no
//! long-running server application that can simply emit logs to
//! stdout and stderr to be picked up by a logging system or a
//! service manager such as systemd. Instead stdout and stderr
//! are returned to the user calling this application via SSH.
//! To provide insights on the server side, errors and info messages
//! have to be sent to a logging system "manually", which can
//! be thought of as a third way to emit messages beside stdout and
//! stderr.
//! This is achieved using the `logger` program which takes care
//! of the heavy lifting here. Logs emitted this way will find their
//! way into the journal on systemd-based systems.
//! Other code parts decide independently if a log message is to
//! be logged on the server side only or also printed to the
//! inherited stdout and stderr file descriptors via SSH.
use crate::types::User;
use std::time::SystemTime;

pub fn error(
    timer: SystemTime,
    user: Option<&User>,
    error: &anyhow::Error,
) -> Result<(), anyhow::Error> {
    std::process::Command::new("logger")
        .args([
            "-p",
            "user.err",
            "-t",
            clap::crate_name!(),
            &format!(
                "message=\"{}\" duration_ns={} user={}",
                error
                    .chain()
                    .map(|error| error.to_string())
                    .collect::<Vec<String>>()
                    .join("; ")
                    .trim(),
                timer.elapsed()?.as_nanos(),
                user.map(|v| v.name.as_str()).unwrap_or("null")
            ),
        ])
        .spawn()?;

    Ok(())
}
