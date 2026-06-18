use std::{error::Error, fmt, io};

use crate::config::validate;

#[derive(Debug)]
pub enum ConfigError {
    Parse {
        message: String,
        file: Option<String>,
        line: Option<usize>,
        column: Option<usize>,
    },
    Validation {
        code: &'static str,
        message: String,
    },
    Io {
        message: String,
    },
}

impl ConfigError {
    pub fn parse(message: impl Into<String>) -> Self {
        Self::Parse {
            message: message.into(),
            file: None,
            line: None,
            column: None,
        }
    }

    #[allow(unused)]
    pub fn with_file(mut self, path: impl Into<String>) -> Self {
        if let Self::Parse { ref mut file, .. } = self {
            *file = Some(path.into());
        }
        self
    }

    pub fn with_pos(mut self, line: usize, column: usize) -> Self {
        if let Self::Parse { line: ref mut l, column: ref mut c, .. } = self {
            *l = Some(line);
            *c = Some(column);
        }
        self
    }

    #[allow(unused)]
    pub fn validation(code: &'static str, message: impl Into<String>) -> Self {
        Self::Validation { code, message: message.into() }
    }

    #[allow(unused)]
    pub fn io(message: impl Into<String>) -> Self {
        Self::Io { message: message.into() }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { message, file, line, column } => {
                if let Some(file) = file {
                    write!(f, "{}", file)?;
                    if let (Some(l), Some(c)) = (line, column) {
                        write!(f, ":{}:{}", l, c)?;
                    }
                    writeln!(f, ":")?;
                    write!(f, "  {}", message)
                } else if let (Some(l), Some(c)) = (line, column) {
                    write!(f, "line {}:{}: {}", l, c, message)
                } else {
                    write!(f, "{}", message)
                }
            },
            Self::Validation { code, message } => {
                write!(f, "error[{}]: {}", code, message)
            },
            Self::Io { message } => write!(f, "{}", message),
        }
    }
}

impl Error for ConfigError {}

impl<R: pest::RuleType> From<pest::error::Error<R>> for ConfigError {
    fn from(err: pest::error::Error<R>) -> Self {
        let (line, column) = match err.line_col {
            pest::error::LineColLocation::Pos((l, c)) => (Some(l), Some(c)),
            pest::error::LineColLocation::Span((l, c), _) => (Some(l), Some(c)),
        };

        Self::Parse { message: err.to_string(), file: None, line, column }
    }
}

impl From<&str> for ConfigError {
    fn from(s: &str) -> Self {
        Self::parse(s)
    }
}

impl From<String> for ConfigError {
    fn from(s: String) -> Self {
        Self::parse(s)
    }
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> Self {
        Self::Io { message: err.to_string() }
    }
}

impl From<validate::ConfigError> for ConfigError {
    fn from(e: validate::ConfigError) -> Self {
        Self::Validation { code: e.code.as_str(), message: e.message }
    }
}
