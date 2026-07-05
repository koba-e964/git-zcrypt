use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::msg(error.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Self::msg(error.to_string())
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(error: std::str::Utf8Error) -> Self {
        Self::msg(error.to_string())
    }
}

pub trait Context<T> {
    fn context(self, context: impl fmt::Display) -> Result<T>;
    fn with_context<C, F>(self, context: F) -> Result<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C;
}

impl<T, E> Context<T> for std::result::Result<T, E>
where
    E: fmt::Display,
{
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.map_err(|error| Error::msg(format!("{context}: {error}")))
    }

    fn with_context<C, F>(self, context: F) -> Result<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C,
    {
        self.map_err(|error| Error::msg(format!("{}: {error}", context())))
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.ok_or_else(|| Error::msg(context.to_string()))
    }

    fn with_context<C, F>(self, context: F) -> Result<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C,
    {
        self.ok_or_else(|| Error::msg(context().to_string()))
    }
}

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error::Error::msg(format!($($arg)*)))
    };
}

#[macro_export]
macro_rules! ensure {
    ($condition:expr, $($arg:tt)*) => {
        if !$condition {
            $crate::bail!($($arg)*);
        }
    };
}
