#[derive(Debug)]
pub struct Error {
    inner: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl Error {
    #[inline]
    pub fn new<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Error { inner: err.into() }
    }

    #[inline]
    pub fn inner(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        &*self.inner
    }

    #[inline]
    pub fn take_inner(self) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self.inner
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}
