use std::borrow::Cow;

#[derive(Clone, Debug)]
pub struct Error(Cow<'static, str>);

impl Error {
    pub fn from_cow(s: Cow<'static, str>) -> Self {
        Error(s)
    }
    pub fn into_cow(self) -> Cow<'static, str> {
        self.0
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

#[cfg(feature = "ed25519-dalek")]
impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(e: ed25519_dalek::ed25519::Error) -> Self {
        Self::from_cow(e.to_string().into())
    }
}

impl From<multibase::Error> for Error {
    fn from(e: multibase::Error) -> Self {
        Self::from_cow(e.to_string().into())
    }
}

impl From<multihash::Error> for Error {
    fn from(e: multihash::Error) -> Self {
        Self::from_cow(e.to_string().into())
    }
}

#[cfg(feature = "p521")]
impl From<p521::ecdsa::Error> for Error {
    fn from(e: p521::ecdsa::Error) -> Self {
        Self::from_cow(e.to_string().into())
    }
}

#[cfg(feature = "signature-dyn")]
impl From<signature_dyn::Error> for Error {
    fn from(e: signature_dyn::Error) -> Self {
        Self::from_cow(e.into_cow())
    }
}

impl From<ssi_multicodec::Error> for Error {
    fn from(e: ssi_multicodec::Error) -> Self {
        Self::from_cow(e.to_string().into())
    }
}

#[macro_export]
macro_rules! error {
    ($fmt:literal) => {
        $crate::Error::from_cow(std::borrow::Cow::Borrowed($fmt))
    };
    ($fmt:literal, $($arg:tt)*) => {
        $crate::Error::from_cow(std::borrow::Cow::Owned(format!($fmt, $($arg)*)))
    };
}

#[macro_export]
macro_rules! bail {
    ($fmt:literal) => {{
        return Err($crate::error!($fmt));
    }};
    ($fmt:literal, $($arg:tt)*) => {{
        return Err($crate::error!($fmt, $($arg)*));
    }};
}

#[macro_export]
macro_rules! ensure {
    ($condition: expr, $fmt:literal) => {
        if !$condition {
            $crate::bail!($fmt);
        }
    };
    ($condition: expr, $fmt:literal, $($arg:tt)*) => {
        if !$condition {
            $crate::bail!($fmt, $($arg)*);
        }
    };
}
