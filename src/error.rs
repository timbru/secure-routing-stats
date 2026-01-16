//! Generic Error for this application

//------------ Error --------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    WithMessage(String),
}

impl Error {
    pub fn msg(s: impl std::fmt::Display) -> Self {
        Error::WithMessage(s.to_string())
    }
}
