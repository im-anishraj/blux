use clap::Parser;

/// A runtime platform that makes executing unknown software safe by default.
///
/// Wrap any command with `bulx` to observe, analyse, and enforce security
/// policies on its runtime behaviour.
///
/// Usage:
///   bulx [OPTIONS] [--] <COMMAND> [ARGS...]
///
/// Examples:
///   bulx npm install express
///   bulx pip install requests
///   bulx python script.py
///   bulx ./unknown-binary
#[derive(clap::ValueEnum, Clone, Debug, Default, PartialEq)]
pub enum Format {
    #[default]
    Human,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "bulx",
    version,
    about = "Execute any command safely.",
    long_about = "A runtime platform that makes executing unknown software safe by default.\n\n\
        Wrap any command with bulx to observe, analyse, and enforce security policies\n\
        on its runtime behaviour.",
    after_help = "Examples:\n  bulx npm install express\n  bulx pip install requests\n  bulx ./unknown-binary",
    trailing_var_arg = true
)]
pub struct Cli {
    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Enable audit mode (trace syscalls and report behaviour)
    #[arg(short, long, group = "mode")]
    pub audit: bool,

    /// Enable enforce mode (block policy violations via kernel sandbox)
    #[arg(short, long, group = "mode")]
    pub enforce: bool,

    /// Output format for audit report
    #[arg(short, long, value_enum, default_value_t = Format::Human)]
    pub format: Format,

    /// Path to the policy configuration file (defaults to bulx.toml if it exists)
    #[arg(short, long)]
    pub policy: Option<String>,

    /// The command and its arguments to execute
    #[arg(required = true, num_args = 1..)]
    pub command: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_command() {
        let cli = Cli::parse_from(["bulx", "echo", "hello"]);
        assert_eq!(cli.command, vec!["echo", "hello"]);
        assert_eq!(cli.verbose, 0);
    }

    #[test]
    fn parse_with_separator() {
        let cli = Cli::parse_from(["bulx", "--", "echo", "hello"]);
        assert_eq!(cli.command, vec!["echo", "hello"]);
    }

    #[test]
    fn parse_verbose() {
        let cli = Cli::parse_from(["bulx", "-vvv", "ls"]);
        assert_eq!(cli.verbose, 3);
        assert_eq!(cli.command, vec!["ls"]);
    }

    #[test]
    fn parse_command_with_flags() {
        let cli = Cli::parse_from(["bulx", "--", "ls", "-la", "/tmp"]);
        assert_eq!(cli.command, vec!["ls", "-la", "/tmp"]);
    }
}
