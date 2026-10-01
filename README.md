# stassh

This is a personal project aimed at discovering how OpenSSH can be leveraged as a secure network transport and authentication tool when building CLI tools.

The `stassh` secret manager is a simple CRUD application that is accessed via `ssh` to manage passwords and secrets with a CLI. In the background the heavy lifting is left to [`systemd-creds`](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html), which manages encryption and decryption of secrets. The words passwords and secrets are used interchangebly here, because `systemd-creds` does not differentiate between the two. It just encrypts whatever input is thrown at it. Thus `stassh` is suitable for both kinds of inputs, individual user passwords and sensitive files.

The application can be used to store private and group-accessible passwords and secrets. Two workspaces separate the two:

- `priv:/`
- `pub:/`

A minimal amount of access control ensures that individual clients only see and modify the secrets they are explicitly allowed to in the group-accessible workspace. Meanwhile the private workspace of each individual can be modified by them without restrictions, of course.

## How it works

On the client side the OpenSSH client `ssh` is used to interact with `stassh` on the server side. Since `stassh` is a CLI tool, CLI arguments and options are passed to `ssh` which in turn passes them on to the `stassh` process once its started. For example:

```sh
# Show usage.
$ ssh stassh@example.org help

# Show usage on the `list` subcommand.
$ ssh stassh@example.org help list

# Use the `list` subcommand to show existing secrets in this path.
$ ssh stassh@example.org list priv:/

# Create a secret in the private workspace.
$ echo -n "foobar" | ssh stassh@example.org create priv:/path/to/my-secret

# Retrieve a secret from the private workspace.
$ ssh stassh@example.org get priv:/path/to/my-secret
foobar
```

Thus `ssh` can be used to interact with the remote application as if it were a local CLI tool.

On the server side, once `stassh` is installed, a `Match` block inside the OpenSSH configuration forces the SSH server to execute `stassh` whenever a user by the same name authenticates successfully. All arguments supplied by the user to the remote command are passed on to `stassh` which interprets them, just like a local CLI tool would if it were invoked in a local shell instead of via `ssh`. The OpenSSH configuration snippet responsible for running `stassh` looks as follows:

```
# /etc/ssh/sshd_config.d/stassh.conf

Match User stassh
  Banner none
  ForceCommand /usr/bin/stassh
  ExposeAuthInfo yes
  AuthenticationMethods publickey
```

OpenSSH exposes the public key that was used for authentication to `stassh` so the application is able to associate the public key with a specific user.

> Caveat: For this to work the public key must be present in both the `AuthorizedKeysFile` and `/etc/stassh/users.yml`. See below for details.

## Building

Once a Rust toolchain is installed via `cargo`, the application and the DEB package can be built with:

```sh
$ cargo install cargo-deb
$ cargo deb -p stassh
```

## Installation

The application is designed to run on systemd-enabled Debian servers only.

1. Install the DEB package on the server:

```sh
$ dpkg -i <path-to-deb>
```

2. Inspect the `sshd` configuration snippet in `/etc/ssh/sshd_config.d/stassh.conf` and tailor it to your needs. Note the comments in the file regarding mandatory directives that are needed for `stassh` to function properly.

> The DEB package also installs `systemd.path` and `systemd.service` units to watch the yet-to-be-created user configuration file at `/etc/stassh/users.yml` and copy the SSH public keys automatically to the `authorized_keys` file used by OpenSSH.

## Configuration

The only configuration file needed right now is the user configuration located at `/etc/stassh/users.yml`. It contains all users that are allowed to access `stassh` in a YAML dictionary with usernames as keys:

```yaml
its-me:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMSYg0pI7YAun+ZlMuDSjfP6iZtF7QQ4lBnhWxlW9WpK
someone-else:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqn7H2niImysX3TcHA7w46p9l3Gulq6AhZK1zxtTFa8
  permissions:
    - path: /
    - path: /nested/folder
      write: true
```

- Users are identified by their SSH keys. Multiple SSH keys can be defined for each user (though the same key cannot be used for multiple users, which will result in silent failure).
- An optional set of permissions determines the paths a user can access. Within the permission set the workspace prefix (`priv:` vs. `pub:`) is omitted, because permissions only ever apply to the public workspace. In the example above `someone-else` can read all secrets in the public workspace (`pub:/`) and can also modify/write secrets in `pub:/nested/folder`. The `write` attribute is optional and defaults to `false`.

> Users without an explicit set of permissions can only access their private workspace at `priv:/`.

## Security

When passing secrets to `stassh` ensure the secret does not show up in cleartext in the shell history. Bash provides a sensible default configuration where prepending a command with whitespace causes the command not to be appended to the shell history.

## Caveats

Since `systemd-creds` uses the local TMP device to encrypt secrets, secrets are not tranferrable. They only live as long as the server they were created on.

Migrating secrets is only possible by `get`ing them from one server and `create`ing them on another, which should work by piping the respective commands:

```sh
$ ssh stassh@old.example.org get pub:/path/to/secret --trim | ssh stassh@new.example.org create pub:/path/to/secret
```
