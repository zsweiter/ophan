use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub enum Command {
    Version,
    Test,
    Config,
    Doctor,
    Upgrade,
    Signal(Signal),
}

#[derive(Debug, Clone, Copy)]
pub enum Signal {
    Stop,
    Quit,
    Reload,
    Reopen,
}

impl FromStr for Signal {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stop" => Ok(Signal::Stop),
            "quit" => Ok(Signal::Quit),
            "reload" => Ok(Signal::Reload),
            "reopen" => Ok(Signal::Reopen),
            _ => Err("Invalid signal string"),
        }
    }
}

#[derive(Debug, Default)]
pub struct CliArgs {
    pub config: Option<String>,
}

pub fn parse_cli(version: &str) -> (Option<Command>, CliArgs) {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut cli = CliArgs::default();
    let mut cmd: Option<Command> = None;

    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help_and_exit(version);
            },

            "-v" | "--version" => cmd = Some(Command::Version),

            "-t" | "--test" => cmd = Some(Command::Test),

            "--config" | "-c" => {
                if let Some(v) = args.get(i + 1) {
                    cli.config = Some(v.clone());
                    i += 1;
                } else {
                    eprintln!("Error: The '{}' flag requires a configuration file path.", args[i]);
                    std::process::exit(1);
                }

                if cmd.is_none() {
                    cmd = Some(Command::Config);
                }
            },

            "--doctor" => cmd = Some(Command::Doctor),

            "--upgrade" => cmd = Some(Command::Upgrade),

            "--signal" | "-s" => {
                if let Some(v) = args.get(i + 1) {
                    cmd = Some(Command::Signal(Signal::from_str(v).unwrap_or_else(|_| {
                        eprintln!("Error: Invalid signal. Available options: stop | quit | reload | reopen");
                        std::process::exit(1);
                    })));

                    i += 1;
                } else {
                    eprintln!("Error: The '{}' flag requires a signal value.", args[i]);
                    std::process::exit(1);
                }
            },

            command => {
                eprintln!("Error: Unknown command or argument '{command}'");
                print_help_and_exit(version);
            },
        }

        i += 1;
    }

    if let Some(Command::Test | Command::Config) = cmd
        && cli.config.is_none()
    {
        eprintln!("Error: The selected command requires a configuration file path via -c or --config.");
        std::process::exit(1);
    }

    (cmd, cli)
}

fn print_help_and_exit(version: &str) -> ! {
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

    std::process::exit(0);
}
