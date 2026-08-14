use std::str::FromStr;

use crate::sys::Signal;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum Command {
    #[default]
    None,
    Test,
    Config,
    Doctor,
    Upgrade,
    Signal(Signal),
}

#[derive(Debug, Default)]
pub struct CliApp {
    pub config: Option<String>,
    pub cmd: Command,
}

impl CliApp {
    pub fn parse() -> Self {
        let version = env!("CARGO_PKG_VERSION");

        let args: Vec<String> = std::env::args().skip(1).collect();

        let mut cli = CliApp::default();
        let mut i = 0;

        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => {
                    print_help(version);
                    std::process::exit(0);
                },

                "-v" | "--version" => {
                    println!(r"Ophan v{version} — A lightweight, high-performance API gateway.");
                    std::process::exit(0);
                },

                "-t" | "--test" => cli.cmd = Command::Test,

                "--config" | "-c" => {
                    if let Some(v) = args.get(i + 1) {
                        cli.config = Some(v.clone());
                        i += 1;
                    } else {
                        eprintln!("Error: The '{}' flag requires a configuration file path.", args[i]);
                        std::process::exit(1);
                    }

                    cli.cmd = Command::Config;
                },

                "--doctor" => cli.cmd = Command::Doctor,

                "--upgrade" => cli.cmd = Command::Upgrade,

                "--signal" | "-s" => {
                    if let Some(v) = args.get(i + 1) {
                        cli.cmd = Command::Signal(Signal::from_str(v).unwrap_or_else(|_| {
                            eprintln!("Error: Invalid signal. Available options: stop | quit | reload | reopen");
                            std::process::exit(1);
                        }));

                        i += 1;
                    } else {
                        eprintln!("Error: The '{}' flag requires a signal value.", args[i]);
                        std::process::exit(1);
                    }
                },

                command => {
                    eprintln!("Error: Unknown command or argument '{command}'");
                    std::process::exit(1);
                },
            }

            i += 1;
        }

        if let Command::Test | Command::Config = cli.cmd
            && cli.config.is_none()
        {
            eprintln!("Error: The selected command requires a configuration file path via -c or --config.");
            std::process::exit(1);
        }

        cli
    }
}

fn print_help(version: &str) {
    println!(
        r#"Ophan v{version} — A lightweight, high-performance API gateway.

USAGE:
  ophan [options]
  ophan -c, --config <file>
  ophan -t, --test -c <file>
  ophan -s, --signal <signal>

OPTIONS:
  -c, --config <file>        Path to the gateway configuration file
  -t, --test                 Validate configuration syntax (requires -c)
  -s, --signal <signal>      Send a control signal to a running instance
      --doctor               Run diagnostics and system health checks
      --upgrade              Hot-reload and upgrade the gateway binary
  -v, --version              Show version information
  -h, --help                 Show this help message

SIGNALS:
  stop                       Stop the gateway immediately
  quit                       Gracefully shut down the gateway
  reload                     Reload the configuration file live
  reopen                     Reopen log files

EXAMPLES:
  # Test a configuration file's syntax
  ophan -t -c ./config.conf

  # Reload configuration on a running instance
  ophan --signal reload

  # Run diagnostic health checks
  ophan --doctor
"#,
        version = version
    );
}
