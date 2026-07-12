use crate::error::{Context, Result};
use crate::{bail, ensure};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug)]
pub(crate) struct Cli {
    pub(crate) command: Command,
}

#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Init,
    InitManifest { path: PathBuf },
    GenerateKey { key: String },
    ImportKey { key: String, input: PathBuf },
    DeriveKey { key: String, stdin: bool },
    ExportKey { key: String, output: PathBuf },
    DeleteKey { key: String },
    InstallFilter { key: String },
    Status,
    Clean { key: String, path: PathBuf },
    Smudge { path: PathBuf },
}

impl Cli {
    pub(crate) fn parse_env() -> Result<Self> {
        Self::try_parse_from(env::args_os())
    }

    fn try_parse_from<I, S>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut args = Args::new(args);
        let command = args
            .next_string("missing command")?
            .context("missing command")?;
        let command = match command.as_str() {
            "--help" | "-h" => {
                args.expect_empty("help")?;
                Command::Help
            }
            "init" => {
                args.expect_empty("init")?;
                Command::Init
            }
            "init-manifest" => Command::InitManifest {
                path: parse_optional_path("init-manifest", &mut args)?,
            },
            "generate-key" => Command::GenerateKey {
                key: parse_key_only("generate-key", &mut args, true)?,
            },
            "import-key" => {
                let (key, input) = parse_key_and_path("import-key", &mut args, "--input")?;
                Command::ImportKey { key, input }
            }
            "derive-key" => {
                let (key, stdin) = parse_derive_key(&mut args)?;
                Command::DeriveKey { key, stdin }
            }
            "export-key" => {
                let (key, output) = parse_key_and_path("export-key", &mut args, "--output")?;
                Command::ExportKey { key, output }
            }
            "delete-key" => Command::DeleteKey {
                key: parse_key_only("delete-key", &mut args, true)?,
            },
            "install-filter" => Command::InstallFilter {
                key: parse_key_only("install-filter", &mut args, true)?,
            },
            "status" => {
                args.expect_empty("status")?;
                Command::Status
            }
            "clean" => {
                let (key, path) = parse_key_and_path("clean", &mut args, "--path")?;
                Command::Clean { key, path }
            }
            "smudge" => Command::Smudge {
                path: parse_required_path("smudge", &mut args, "--path")?,
            },
            _ => bail!("unknown command '{command}'\n\n{}", usage()),
        };
        Ok(Self { command })
    }
}

struct Args {
    args: Vec<OsString>,
    index: usize,
}

impl Args {
    fn new<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        if !args.is_empty() {
            args.remove(0);
        }
        Self { args, index: 0 }
    }

    fn next(&mut self) -> Option<OsString> {
        let arg = self.args.get(self.index)?.clone();
        self.index += 1;
        Some(arg)
    }

    fn next_string(&mut self, context: &str) -> Result<Option<String>> {
        self.next()
            .map(|arg| {
                arg.into_string().map_err(|_| {
                    crate::error::Error::msg(format!("{context}: argument is not UTF-8"))
                })
            })
            .transpose()
    }

    fn expect_empty(&self, command: &str) -> Result<()> {
        ensure!(
            self.index == self.args.len(),
            "{command}: unexpected argument '{}'",
            self.args[self.index].to_string_lossy()
        );
        Ok(())
    }
}

fn parse_key_only(command: &str, args: &mut Args, allow_name_alias: bool) -> Result<String> {
    let mut key = None;
    while let Some(arg) = args.next() {
        let (option, inline_value) = parse_option(command, arg)?;
        if option == "--key" || (allow_name_alias && option == "--name") {
            set_once(
                command,
                option,
                &mut key,
                option_string_value(command, option, inline_value, args)?,
            )?;
        } else {
            bail!("{command}: unexpected option '{option}'");
        }
    }
    key.context(format!("{command}: missing --key"))
}

fn parse_key_and_path(
    command: &str,
    args: &mut Args,
    path_option: &'static str,
) -> Result<(String, PathBuf)> {
    let mut key = None;
    let mut path = None;
    while let Some(arg) = args.next() {
        let (option, inline_value) = parse_option(command, arg)?;
        if option == "--key" || option == "--name" {
            set_once(
                command,
                option,
                &mut key,
                option_string_value(command, option, inline_value, args)?,
            )?;
        } else if option == path_option {
            set_once(
                command,
                option,
                &mut path,
                PathBuf::from(option_value(command, option, inline_value, args)?),
            )?;
        } else {
            bail!("{command}: unexpected option '{option}'");
        }
    }
    let key = key.context(format!("{command}: missing --key"))?;
    let path = path.context(format!("{command}: missing {path_option}"))?;
    Ok((key, path))
}

fn parse_optional_path(command: &str, args: &mut Args) -> Result<PathBuf> {
    let mut path = None;
    while let Some(arg) = args.next() {
        let (option, inline_value) = parse_option(command, arg)?;
        if option == "--path" {
            set_once(
                command,
                option,
                &mut path,
                PathBuf::from(option_value(command, option, inline_value, args)?),
            )?;
        } else {
            bail!("{command}: unexpected option '{option}'");
        }
    }
    Ok(path.unwrap_or_else(|| PathBuf::from(".")))
}

fn parse_required_path(
    command: &str,
    args: &mut Args,
    path_option: &'static str,
) -> Result<PathBuf> {
    let mut path = None;
    while let Some(arg) = args.next() {
        let (option, inline_value) = parse_option(command, arg)?;
        if option == path_option {
            set_once(
                command,
                option,
                &mut path,
                PathBuf::from(option_value(command, option, inline_value, args)?),
            )?;
        } else {
            bail!("{command}: unexpected option '{option}'");
        }
    }
    path.context(format!("{command}: missing {path_option}"))
}

fn parse_derive_key(args: &mut Args) -> Result<(String, bool)> {
    let command = "derive-key";
    let mut key = None;
    let mut stdin = false;
    while let Some(arg) = args.next() {
        let (option, inline_value) = parse_option(command, arg)?;
        if option == "--key" || option == "--name" {
            set_once(
                command,
                option,
                &mut key,
                option_string_value(command, option, inline_value, args)?,
            )?;
        } else if option == "--stdin" {
            ensure!(
                inline_value.is_none(),
                "{command}: --stdin does not take a value"
            );
            stdin = true;
        } else {
            bail!("{command}: unexpected option '{option}'");
        }
    }
    Ok((key.context("derive-key: missing --key")?, stdin))
}

fn parse_option(command: &str, arg: OsString) -> Result<(&'static str, Option<OsString>)> {
    let arg = arg
        .into_string()
        .map_err(|_| crate::error::Error::msg(format!("{command}: option is not UTF-8")))?;
    ensure!(
        arg.starts_with("--"),
        "{command}: unexpected positional argument '{arg}'"
    );
    let (name, value) = match arg.split_once('=') {
        Some((name, value)) => (name, Some(OsString::from(value))),
        None => (arg.as_str(), None),
    };
    let option = match name {
        "--key" => "--key",
        "--name" => "--name",
        "--input" => "--input",
        "--output" => "--output",
        "--stdin" => "--stdin",
        "--path" => "--path",
        _ => bail!("{command}: unknown option '{name}'"),
    };
    Ok((option, value))
}

fn option_value(
    command: &str,
    option: &str,
    inline_value: Option<OsString>,
    args: &mut Args,
) -> Result<OsString> {
    match inline_value {
        Some(value) => Ok(value),
        None => args
            .next()
            .with_context(|| format!("{command}: missing value for {option}")),
    }
}

fn option_string_value(
    command: &str,
    option: &str,
    inline_value: Option<OsString>,
    args: &mut Args,
) -> Result<String> {
    option_value(command, option, inline_value, args)?
        .into_string()
        .map_err(|_| {
            crate::error::Error::msg(format!("{command}: value for {option} is not UTF-8"))
        })
}

fn set_once<T>(command: &str, option: &str, target: &mut Option<T>, value: T) -> Result<()> {
    ensure!(target.is_none(), "{command}: duplicate {option}");
    *target = Some(value);
    Ok(())
}

pub(crate) fn usage() -> &'static str {
    "Usage:
  git-zcrypt init
  git-zcrypt init-manifest [--path <dir>]
  git-zcrypt generate-key --key <name>
  git-zcrypt import-key --key <name> --input <path>
  git-zcrypt derive-key --key <name> [--stdin]
  git-zcrypt export-key --key <name> --output <path>
  git-zcrypt delete-key --key <name>
  git-zcrypt install-filter --key <name>
  git-zcrypt status
  git-zcrypt clean --key <name> --path <path>
  git-zcrypt smudge --path <path>"
}

#[cfg(test)]
mod tests {
    use super::Cli;

    #[test]
    fn parses_planned_subcommands() {
        for args in [
            vec!["git-zcrypt", "init"],
            vec!["git-zcrypt", "init-manifest"],
            vec!["git-zcrypt", "init-manifest", "--path", "secrets/team-a"],
            vec!["git-zcrypt", "generate-key", "--key", "default"],
            vec![
                "git-zcrypt",
                "import-key",
                "--key",
                "default",
                "--input",
                "key.bin",
            ],
            vec!["git-zcrypt", "derive-key", "--key", "default"],
            vec!["git-zcrypt", "derive-key", "--key", "default", "--stdin"],
            vec![
                "git-zcrypt",
                "export-key",
                "--key",
                "default",
                "--output",
                "key.bin",
            ],
            vec!["git-zcrypt", "delete-key", "--key", "default"],
            vec!["git-zcrypt", "install-filter", "--key", "default"],
            vec!["git-zcrypt", "status"],
            vec![
                "git-zcrypt",
                "clean",
                "--key",
                "default",
                "--path",
                "secrets/a.txt",
            ],
            vec!["git-zcrypt", "smudge", "--path", "secrets/a.txt"],
        ] {
            Cli::try_parse_from(args).expect("subcommand should parse");
        }
    }

    #[test]
    fn parses_key_option_for_key_commands() {
        for args in [
            vec!["git-zcrypt", "generate-key", "--key", "default"],
            vec![
                "git-zcrypt",
                "import-key",
                "--key",
                "default",
                "--input",
                "key.bin",
            ],
            vec!["git-zcrypt", "derive-key", "--key", "default"],
            vec!["git-zcrypt", "derive-key", "--key", "default", "--stdin"],
            vec![
                "git-zcrypt",
                "export-key",
                "--key",
                "default",
                "--output",
                "key.bin",
            ],
            vec!["git-zcrypt", "delete-key", "--key", "default"],
            vec!["git-zcrypt", "install-filter", "--key", "default"],
            vec![
                "git-zcrypt",
                "clean",
                "--key",
                "default",
                "--path",
                "secrets/a.txt",
            ],
        ] {
            Cli::try_parse_from(args).expect("--key should parse");
        }
    }

    #[test]
    fn parser_rejects_missing_and_unexpected_options() {
        for args in [
            vec!["git-zcrypt"],
            vec!["git-zcrypt", "generate-key"],
            vec!["git-zcrypt", "generate-key", "--key"],
            vec![
                "git-zcrypt",
                "generate-key",
                "--key",
                "default",
                "--key",
                "other",
            ],
            vec!["git-zcrypt", "clean", "--name", "default"],
            vec!["git-zcrypt", "status", "--key", "default"],
        ] {
            Cli::try_parse_from(args).expect_err("invalid arguments should fail");
        }
    }
}
