use pest::Span;
use pest::error::Error as PestError;
use pest::error::ErrorVariant;
use pest::iterators::Pair;
use std::{error::Error, fmt, io, path::PathBuf};

#[derive(Debug)]
pub enum ConfigError {
    /// Holds Pest's native error directly.
    Parse {
        pest_err: Box<PestError<super::parser::Rule>>,
        file_path: Option<PathBuf>,
    },
    Validation {
        code: &'static str,
        message: String,
        file_path: Option<PathBuf>,
    },
    Io {
        source: io::Error,
        path: Option<PathBuf>,
        message: Option<String>,
    },
}

impl ConfigError {
    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        let p = Some(path.into());
        match &mut self {
            Self::Parse { file_path, .. } => *file_path = p,
            Self::Validation { file_path, .. } => *file_path = p,
            Self::Io { path, .. } => *path = p,
        }
        self
    }

    /// Renders the error to stderr using Pest's built-in printer.
    pub fn print(&self) {
        eprintln!("{self}");
    }

    pub fn parse(message: impl Into<String>) -> Self {
        Self::Validation { code: "PARSE", message: message.into(), file_path: None }
    }

    pub fn validation(code: &'static str, message: impl Into<String>) -> Self {
        Self::Validation { code, message: message.into(), file_path: None }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { pest_err, file_path } => {
                let mut err = pest_err.clone();
                if let Some(path) = file_path {
                    *err = err.with_path(path.to_string_lossy().as_ref());
                }

                write!(f, "{err}")
            },
            Self::Validation { code, message, file_path } => {
                let path = file_path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "config".into());
                write!(f, "error[{code}]: {message}\n --> {path}")
            },
            Self::Io { source, path, message: _ } => {
                let p = path.as_ref().map(|p| format!(" at {}", p.display())).unwrap_or_default();
                write!(f, "I/O error: {source}{p}")
            },
        }
    }
}

impl Error for ConfigError {}

// Auto-convert any Pest parsing error into ConfigError
impl From<PestError<super::parser::Rule>> for ConfigError {
    fn from(pest_err: PestError<super::parser::Rule>) -> Self {
        Self::Parse { pest_err: Box::new(pest_err), file_path: None }
    }
}

impl From<io::Error> for ConfigError {
    fn from(source: io::Error) -> Self {
        Self::Io { source, path: None, message: None }
    }
}

impl From<String> for ConfigError {
    fn from(msg: String) -> Self {
        Self::Validation { code: "PARSE", message: msg, file_path: None }
    }
}

impl From<std::num::ParseIntError> for ConfigError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::Validation { code: "PARSE", message: value.to_string(), file_path: None }
    }
}

pub trait PairErrExt<'a, R: pest::RuleType> {
    fn error(&self, msg: impl Into<String>) -> ConfigError;
}

impl<'a, R: pest::RuleType> PairErrExt<'a, R> for Pair<'a, R> {
    fn error(&self, msg: impl Into<String>) -> ConfigError {
        PestError::new_from_span(ErrorVariant::CustomError { message: msg.into() }, self.as_span()).into()
    }
}

impl<'a> PairErrExt<'a, super::parser::Rule> for Span<'a> {
    fn error(&self, msg: impl Into<String>) -> ConfigError {
        PestError::new_from_span(ErrorVariant::CustomError { message: msg.into() }, *self).into()
    }
}
