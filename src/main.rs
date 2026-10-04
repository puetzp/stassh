mod auth;
mod error;
mod execute;
mod log;
mod types;
#[cfg(test)]
mod util;

use anyhow::Context;
use clap::{Arg, Command};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    time::SystemTime,
};
use types::{PrefixedPath, User, Verb};

/// The main function authenticates the user and then passes the
/// remainder of the processing application flow to the `run` function.
/// Wrapping the remaining logic in another function is necessary to
/// be able to handle errors properly and hand over the user context
/// that is created early on.
fn main() -> Result<(), anyhow::Error> {
    // Statically defined file and directory paths.
    // The program expects the parent directories to exist, which are
    // to be created by other means, such as install scripts.
    let lock_file = Path::new("/var/lib/stassh/lock");
    let data_dir = PathBuf::from("/var/lib/stassh/data");
    let users_file = Path::new("/etc/stassh/users.yml");

    // TODO: Check if directories exist and are writable.

    // The timer is used to estimate the duration that the program
    // took to process the user request.
    let timer = SystemTime::now();

    // Authenticate the user by leveraging the `ExposeAuthInfo`
    // directive from OpenSSH.
    // When this fails the error is logged differently than any
    // other errors that may appear later on, because at this
    // stage the user is unauthenticated. Only a part of the
    // error chain is returned to the user.
    let user = match auth::authenticate(&users_file) {
        Ok(user) => user,
        Err(error) => {
            log::error(timer, None, &error)?;

            match error.downcast::<error::AuthenticationError>() {
                Ok(_error) => anyhow::bail!(_error),
                Err(_error) => {
                    log::error(timer, None, &_error)?;
                    anyhow::bail!("internal server error");
                }
            }
        }
    };

    // Pass errors from the wrapped "main" function to
    // the logging system. Only a part of the error chain
    // us returned to the user, depending on if the user
    // action caused the error and is thus recoverable
    // by adjusting the command sent via SSH. Unrecoverable
    // errors are not returned to the user because the no
    // amount of information enables the user to solve the
    // problem themselves.
    // This could be the case when:
    // * a bug is encountered
    // * not all requirements are fulfilled that the
    //   application can function properly, e.g. changed
    //   filesystem permissions.
    if let Err(error) = run(&lock_file, &data_dir, &user) {
        log::error(timer, Some(&user), &error)?;

        match error.downcast::<error::UserError>() {
            Ok(_error) => anyhow::bail!(_error),
            Err(_error) => {
                log::error(timer, None, &_error)?;
                anyhow::bail!("internal server error");
            }
        }
    }

    Ok(())
}

/// This function runs the application logic after user authentication.
/// So every step taken here can be assumed to run in an authenticated
/// user context.
/// The function parses command line arguments, shell-normalized via
/// `shlex`, and retains the verb that determines the next action and
/// creates the lock file before executing the action.
/// Before returning the result from the action, the lock file is
/// cleaned up.
fn run(lock_file: &Path, data_dir: &PathBuf, user: &User) -> Result<(), anyhow::Error> {
    // Let another mechanism create the parent directory, but ensure
    // the data directory exists before continuing.
    if !data_dir.try_exists().context(format!(
        "failed to determine if data directory `{}` exists",
        &data_dir.display()
    ))? {
        fs::create_dir(&data_dir).context(format!(
            "failed to create data directory `{}`",
            data_dir.display()
        ))?;
    }

    // Build the command and subcommand tree using the builder
    // API from clap.
    let command = clap::command!()
        .version(clap::crate_version!())
        .long_about(clap::crate_description!())
        .no_binary_name(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("create")
                .about("Create a new secret from standard input, encrypting it in the process")
                .arg(
                    Arg::new("path")
                        .help("Path to secret")
                        .value_parser(clap::value_parser!(PrefixedPath))
                        .required(true),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("update")
                .about(
                    "Update an existing secret from standard input, encrypting it in the process",
                )
                .arg(
                    Arg::new("path")
                        .help("Path to secret")
                        .value_parser(clap::value_parser!(PrefixedPath))
                        .required(true),
                )
                .arg(
                    Arg::new("create")
                        .short('c')
                        .long("create")
                        .help("Create the secret if it does not exist")
                        .action(clap::ArgAction::SetTrue)
                        .required(false),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete an existing secret")
                .arg(
                    Arg::new("path")
                        .help("Path to secret")
                        .value_parser(clap::value_parser!(PrefixedPath))
                        .required(true),
                )
                .arg(
                    Arg::new("force")
                        .short('f')
                        .long("force")
                        .help("Force removal of non-empty directories")
                        .action(clap::ArgAction::SetTrue)
                        .required(false),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("get")
                .about("Get an existing secret in decrypted form")
                .arg(
                    Arg::new("path")
                        .help("Path to secret")
                        .value_parser(clap::value_parser!(PrefixedPath))
                        .required(true),
                )
                .arg(
                    Arg::new("trim")
                        .short('t')
                        .long("trim")
                        .help("Do not output the trailing newline")
                        .action(clap::ArgAction::SetTrue)
                        .required(false),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("list")
                .alias("ls")
                .about("List available paths to existing secrets")
                .arg(
                    Arg::new("path")
                        .help("Path to secret or directory")
                        .value_parser(clap::value_parser!(PrefixedPath))
                        .required(true),
                )
                .arg_required_else_help(true),
        );

    // OpenSSH's ForceCommand is used to execute the application.
    // In this context the application is not really called with
    // the arguments that were supplied by the user. Instead the
    // arguments are moved to this environment variable. The
    // variable can then be read by the application to determine
    // if the command can be executed safely.
    // In our case all arguments from the command line are passed
    // to the clap parser for validation.
    let original_command = std::env::var("SSH_ORIGINAL_COMMAND")
        .context("failed to read command supplied by the user from SSH_ORIGINAL_COMMAND")?;

    // Split the command line passed to the application by
    // ForceCommand into separate tokens, mimicking shell-escaping
    // and considering quoted, multi-word arguments.
    let words =
        shlex::split(&original_command).ok_or(anyhow::anyhow!(error::UserError::new(format!(
            "failed to parse arguments from command `{}` in a POSIX-like manner, e.g. due to wrong quoting",
            original_command
        ))))?;

    // Let clap parse the command line arguments and panic when
    // it fails. This is fine at this stage where the lock does
    // not exist yet and no cleanup is needed on failure.
    let matches = command.clone().get_matches_from(words);

    let verb = match matches.subcommand() {
        Some(("create", sub_m)) => {
            let path = sub_m
                .get_one::<PrefixedPath>("path")
                .expect("`path` is required");
            Verb::Create { path: path.clone() }
        }
        Some(("update", sub_m)) => {
            let path = sub_m
                .get_one::<PrefixedPath>("path")
                .expect("`path` is required");
            let create = sub_m.get_flag("create");
            Verb::Update {
                path: path.clone(),
                create,
            }
        }
        Some(("delete", sub_m)) => {
            let path = sub_m
                .get_one::<PrefixedPath>("path")
                .expect("`path` is required");
            let force = sub_m.get_flag("force");
            Verb::Delete {
                path: path.clone(),
                force,
            }
        }
        Some(("get", sub_m)) => {
            let path = sub_m
                .get_one::<PrefixedPath>("path")
                .expect("`path` is required");
            let trim = sub_m.get_flag("trim");
            Verb::Get {
                path: path.clone(),
                trim,
            }
        }
        Some(("list", sub_m)) => {
            let path = sub_m
                .get_one::<PrefixedPath>("path")
                .expect("`path` is required");
            Verb::List { path: path.clone() }
        }
        _ => unreachable!(),
    };

    // Before continuing, acquire a lock to enter the
    // critical section. Not every of the immediate following
    // steps is necessarily critical in the sense of risking
    // data corruption or timing problems. But since the
    // application does not need to handle large throughput,
    // the lock can be used for any subsequent operation, even
    // plain read operations, to keep the application flow
    // simple.
    // Check multiple times in a row if a lock file already exists.
    // If it exists, another user is using the program. Since
    // operations should usually be short-lived, simply retrying
    // until the lock file is removed should be sufficient
    // for the moment.
    //
    // TODO: Capture the SIGTERM signal to ensure the code for removing
    // the lock file is run when a user hits ctrl-c mid-operation.
    let mut count = 0;

    loop {
        if let Err(error) = fs::File::create_new(lock_file) {
            if error.kind() == io::ErrorKind::AlreadyExists {
                if count < 10 {
                    count += 1;
                    std::thread::sleep(std::time::Duration::from_millis(100));
                } else {
                    anyhow::bail!("failed to acquire lock");
                }
            } else {
                return Err(error).context("failed to acquire lock file");
            }
        } else {
            break;
        }
    }

    // Capture errors from a function that runs the
    // actual application logic. Simply panicking or bubbling up
    // errors to the calling function is not an option, because
    // the lock needs to be removed before the application exits.
    let result = process(data_dir, verb, user);

    // After all is done, remove the lock file, making the program
    // available for other users.
    fs::remove_file(lock_file).context("failed to remove lock file")?;

    // Return possible errors to the error handling logic
    // of anyhow to print a nice error chain.
    result?;

    Ok(())
}

/// This function is an extra wrapper around the functions that
/// actually process user input.
/// The whole function is equivalent to the critical section,
/// meaning it runs with a file-based lock which is released
/// after this function returns.
/// It is a separate function in order to be able to handle
/// the `Result` more gracefully in the calling function.
fn process(data_dir: &PathBuf, verb: Verb, user: &User) -> Result<(), anyhow::Error> {
    match verb {
        Verb::Create { path } => {
            execute::create(data_dir, &user, &path)?;
        }
        Verb::Update { path, create } => {
            execute::update(data_dir, &user, &path, create)?;
        }
        Verb::Delete { path, force } => {
            execute::delete(data_dir, &user, &path, force)?;
        }
        Verb::Get { path, trim } => {
            execute::get(data_dir, &user, &path, trim)?;
        }
        Verb::List { path } => {
            execute::list(data_dir, &user, &path)?;
        }
    }

    Ok(())
}
