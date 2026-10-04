use anyhow::Context;
use std::{
    ffi::OsStr,
    fmt,
    ops::Deref,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

/// The verb determines the user action. Different verbs
/// take different options, depending on the context.
/// This mostly resembles the command line arguments parsed
/// by clap.
pub enum Verb {
    Create { path: PrefixedPath },
    Update { path: PrefixedPath, create: bool },
    Delete { path: PrefixedPath, force: bool },
    Get { path: PrefixedPath, trim: bool },
    List { path: PrefixedPath },
}

/// The user object contains the username and a set of permissions.
/// The username must adhere to a few rules however as seen in the
/// `FromStr` implementation.
/// The permission set is a sorted list of paths and a boolean flag
/// that indicates if a path is writable.
/// When more than one permission is relevant to determine if a user
/// is allowed to modify an item at a given path, the most significant
/// permission, as determined by its path, wins.
/// This means that a user can be allowed to write to `/some/path` even
/// when `/some` and other sub directories are not writable.
#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub name: Username,
    pub permissions: Vec<Permission>,
}

impl FromStr for User {
    type Err = anyhow::Error;

    /// This parses a string in the format
    ///
    /// ```
    /// <username>
    /// <write> <path>
    /// <write> <path>
    /// ...
    /// ```
    ///
    /// The first line encodes the username while all subsequent
    /// lines make up the set of permissions granted to the user.
    /// The first part of such a line is a boolean flag indicating
    /// write permissions, while the remainder is parsed as a path
    /// that the write permission is applied to.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.lines();

        let username = Username::from_str(
            lines
                .next()
                .ok_or(anyhow::anyhow!("failed to extract username"))?,
        )?;

        let mut permissions = vec![];

        for line in lines {
            let (prefix, suffix) = line
                .split_once(' ')
                .ok_or(anyhow::anyhow!("failed to parse permission"))?;

            let write = bool::from_str(prefix).context("failed to parse `write` as boolean")?;

            let path = PathBuf::from_str(suffix).context("failed to parse `path`")?;

            if !path.is_absolute() {
                anyhow::bail!("path must be absolute");
            }

            if path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
            {
                anyhow::bail!("path must not contain relative path components");
            }

            permissions.push(Permission { path, write });
        }

        permissions.sort_by(|a, b| b.path.cmp(&a.path));

        Ok(Self {
            name: username,
            permissions,
        })
    }
}

impl User {
    /// Return `true` if there is any overlap between the target path's
    /// ancestors and the user's permissions. This suffices as the presence
    /// of a path in a user's set of permissions grants read access implicitly.
    pub fn can_read(&self, path: &PrefixedPath) -> bool {
        match path {
            PrefixedPath::Private(_) => true,
            PrefixedPath::Public(_path) => _path.ancestors().any(|ancestor| {
                self.permissions
                    .iter()
                    .any(|permission| ancestor == permission.path)
            }),
        }
    }

    /// Return `true` if any permission can be found that matches the
    /// most significant ancestor of the path and if this permission
    /// allows the user to write to this path.
    /// Since the set of permissions is in reverse order, this guarantees
    /// that write permissions can be fine-tuned to allow access only
    /// to a nested path whose parent is barred from modification. This
    /// way a user can create secrets in a nested path, but cannot create
    /// new directories/groups/folders.
    pub fn can_write(&self, path: &PrefixedPath) -> bool {
        match path {
            PrefixedPath::Private(_) => true,
            PrefixedPath::Public(_path) => {
                let mut permissions = self.permissions.clone();
                permissions.sort_by(|a, b| b.path.cmp(&a.path));

                _path
                    .ancestors()
                    .find_map(|ancestor| {
                        permissions
                            .iter()
                            .find(|permission| *ancestor == permission.path)
                            .map(|permission| permission.write)
                    })
                    .unwrap_or_default()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Username(String);

impl FromStr for Username {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            anyhow::bail!("username cannot be an empty string")
        }

        if s.chars().count() > 32 {
            anyhow::bail!("username cannot exceed 32 characters")
        }

        if let Some(ref c) = s
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '.' || *c == '_'))
        {
            anyhow::bail!("username contains invalid character `{}`", c)
        }

        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl Deref for Username {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl Username {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Permission {
    pub path: PathBuf,
    pub write: bool,
}

/// When a user supplies a path that they would like to modify
/// or read, it is usually prepended with `priv:` or `pub:`. The
/// former indicates that the secret in question is located in
/// the user's private area, while the latter refers to a "public"
/// secret, meaning a secret that multiple persons may have access
/// to.
/// This object encodes this distinction. A path without a prefix
/// is implicitly converted to a private path to prevent exposing
/// private secrets by accident.
#[derive(Clone, Debug, PartialEq)]
pub enum PrefixedPath {
    Private(PathBuf),
    Public(PathBuf),
}

impl FromStr for PrefixedPath {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn validate_path(path: &str) -> Result<PathBuf, anyhow::Error> {
            let path = PathBuf::from_str(path)?;

            if !path.is_absolute() {
                anyhow::bail!("path must be absolute");
            }

            if path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
            {
                anyhow::bail!("path must not contain relative path components");
            }

            Ok(path)
        }

        if let Some(path) = s.strip_prefix("priv:") {
            Ok(Self::Private(validate_path(path)?))
        } else if let Some(path) = s.strip_prefix("pub:") {
            Ok(Self::Public(validate_path(path)?))
        } else {
            Ok(Self::Private(validate_path(s)?))
        }
    }
}

impl fmt::Display for PrefixedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Private(path) => write!(f, "priv:{}", path.display()),
            Self::Public(path) => write!(f, "pub:{}", path.display()),
        }
    }
}

impl PrefixedPath {
    pub fn is_root(&self) -> bool {
        match self {
            Self::Private(path) => *path == Path::new("/"),
            Self::Public(path) => *path == Path::new("/"),
        }
    }

    /// This converts a user-supplied prefixed path to a real filesystem
    /// path by prepending the data directory path.
    pub fn prepend(&self, user: &User, parent: &PathBuf) -> Result<PathBuf, anyhow::Error> {
        match self {
            Self::Private(path) => Ok(parent
                .join("private")
                .join(user.name.as_str())
                .join(path.strip_prefix("/")?)),
            Self::Public(path) => Ok(parent.join("public").join(path.strip_prefix("/")?)),
        }
    }

    /// This just appends a trailing slash to the path, mainly for
    /// cosmetics, e.g. to make a directory appear more distinct
    /// from a file path.
    ///
    /// TODO: Replace with the original `set_trailing_sep` method
    /// from std once itst stabilized.
    pub fn set_trailing_sep(&mut self) {
        match self {
            Self::Private(path)
                if !path
                    .components()
                    .last()
                    .is_some_and(|component| component == Component::RootDir) =>
            {
                let mut s = format!("{}", path.display());
                s.push('/');
                *path = PathBuf::from(&s);
            }
            Self::Public(path)
                if !path
                    .components()
                    .last()
                    .is_some_and(|component| component == Component::RootDir) =>
            {
                let mut s = format!("{}", path.display());
                s.push('/');
                *path = PathBuf::from(&s);
            }
            _ => {}
        }
    }

    /// This pushes a single path component to the existing path.
    /// It is mostly useful to shorten a real path to a prefixed path by
    /// appending the path components which make up the difference between
    /// the two, e.g.
    ///
    /// ```
    /// real:                   /var/lib/stassh/data/public/some/path
    /// prefixed path:          pub:/
    /// adjusted prefixed path: pub:/some/path
    /// ```
    pub fn push(&mut self, component: &OsStr) {
        match self {
            Self::Private(path) => path.push(component),
            Self::Public(path) => path.push(component),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_prefixed_path() -> Result<(), anyhow::Error> {
        {
            let input = "/some/path";
            let path = PrefixedPath::from_str(input);
            let expected = PrefixedPath::Private(PathBuf::from("/some/path"));
            assert!(path.is_ok_and(|_path| _path == expected));
        }

        {
            let input = "priv:/some/path";
            let path = PrefixedPath::from_str(input);
            let expected = PrefixedPath::Private(PathBuf::from("/some/path"));
            assert!(path.is_ok_and(|_path| _path == expected));
        }

        {
            let input = "pub:/some/path";
            let path = PrefixedPath::from_str(input);
            let expected = PrefixedPath::Public(PathBuf::from("/some/path"));
            assert!(path.is_ok_and(|_path| _path == expected));
        }

        {
            let input = "pub:some/path";
            let path = PrefixedPath::from_str(input);
            assert!(path.is_err());
        }

        {
            let input = "some/path";
            let path = PrefixedPath::from_str(input);
            assert!(path.is_err());
        }

        // References to current directory are not checked. They are
        // normalized by the `FromStr` implementation when it parses the
        // string as `PathBuf` before each path component is checked again.
        // Looking for `.` here is therefore redundant and would result in
        // false positives.
        {
            let input = "pub:/some/../../path";
            let path = PrefixedPath::from_str(input);
            assert!(path.is_err());
        }

        Ok(())
    }

    #[test]
    fn test_prefixed_path_prepend() -> Result<(), anyhow::Error> {
        {
            let mut path = PrefixedPath::Private(PathBuf::from("/some/path"));
            path.push(OsStr::new("secret"));

            let expected = PrefixedPath::Private(PathBuf::from("/some/path/secret"));

            assert_eq!(path, expected);
        }

        Ok(())
    }

    #[test]
    fn test_prefixed_path_push() -> Result<(), anyhow::Error> {
        {
            let path = PrefixedPath::Private(PathBuf::from("/some/secret"));
            let data_dir = PathBuf::from("/foo/bar");
            let user = User {
                name: Username::from_str("someone")?,
                permissions: vec![],
            };
            let expected = Path::new("/foo/bar/private/someone/some/secret");
            assert_eq!(path.prepend(&user, &data_dir)?, expected);
        }

        {
            let path = PrefixedPath::Public(PathBuf::from("/some/secret"));
            let data_dir = PathBuf::from("/foo/bar");
            let user = User {
                name: Username::from_str("someone")?,
                permissions: vec![],
            };
            let expected = Path::new("/foo/bar/public/some/secret");
            assert_eq!(path.prepend(&user, &data_dir)?, expected);
        }

        Ok(())
    }

    #[test]
    fn test_prefixed_path_set_trailing_sep() -> Result<(), anyhow::Error> {
        {
            let mut path = PrefixedPath::Private(PathBuf::from("/some/secret/folder"));
            path.set_trailing_sep();
            let expected = "priv:/some/secret/folder/";
            assert_eq!(format!("{}", path), expected);
        }

        Ok(())
    }

    #[test]
    fn test_user_parsing() -> Result<(), anyhow::Error> {
        {
            let input = r#"my-name
true /foo/bar
false /foo/bar/foo
true /bar
false /bar/foo
"#;
            let user = User::from_str(input)?;
            let expected = User {
                name: Username("my-name".to_string()),
                permissions: vec![
                    Permission {
                        path: PathBuf::from("/foo/bar/foo"),
                        write: false,
                    },
                    Permission {
                        path: PathBuf::from("/foo/bar"),
                        write: true,
                    },
                    Permission {
                        path: PathBuf::from("/bar/foo"),
                        write: false,
                    },
                    Permission {
                        path: PathBuf::from("/bar"),
                        write: true,
                    },
                ],
            };
            assert!(user == expected);
        }

        {
            let input = r#"my-name"#;
            let user = User::from_str(input)?;
            let expected = User {
                name: Username("my-name".to_string()),
                permissions: vec![],
            };
            assert!(user == expected);
        }

        Ok(())
    }

    #[test]
    fn test_user_can_read() -> Result<(), anyhow::Error> {
        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![],
            };

            let path = PrefixedPath::from_str("pub:/")?;

            assert!(!user.can_read(&path));
        }

        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![],
            };

            let path = PrefixedPath::from_str("priv:/")?;

            assert!(user.can_read(&path));
        }

        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![Permission {
                    path: PathBuf::from("/foo/bar"),
                    write: false,
                }],
            };

            let path = PrefixedPath::from_str("pub:/")?;

            assert!(!user.can_read(&path));
        }

        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![Permission {
                    path: PathBuf::from("/"),
                    write: false,
                }],
            };

            let path = PrefixedPath::from_str("pub:/foo/bar")?;

            assert!(user.can_read(&path));
        }

        Ok(())
    }

    #[test]
    fn test_user_can_write() -> Result<(), anyhow::Error> {
        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![],
            };

            let path = PrefixedPath::from_str("pub:/")?;

            assert!(!user.can_write(&path));
        }

        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![],
            };

            let path = PrefixedPath::from_str("priv:/")?;

            assert!(user.can_write(&path));
        }

        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![],
            };

            let path = PrefixedPath::from_str("/")?;

            assert!(user.can_write(&path));
        }

        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![
                    Permission {
                        path: PathBuf::from("/"),
                        write: false,
                    },
                    Permission {
                        path: PathBuf::from("/foo/bar"),
                        write: true,
                    },
                ],
            };

            let path = PrefixedPath::from_str("pub:/foo/bar")?;

            assert!(user.can_write(&path));
        }

        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![
                    Permission {
                        path: PathBuf::from("/"),
                        write: true,
                    },
                    Permission {
                        path: PathBuf::from("/foo/bar"),
                        write: false,
                    },
                ],
            };

            let path = PrefixedPath::from_str("pub:/foo/bar")?;

            assert!(!user.can_write(&path));
        }

        {
            let user = User {
                name: Username::from_str("me")?,
                permissions: vec![Permission {
                    path: PathBuf::from("/"),
                    write: true,
                }],
            };

            let path = PrefixedPath::from_str("pub:/foo/bar")?;

            assert!(user.can_write(&path));
        }

        Ok(())
    }
}
