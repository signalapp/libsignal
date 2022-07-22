//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::error::Error;
use std::marker::PhantomData;

/// An opaque error that allows context to be attached.
///
/// A very stripped down version of [`anyhow::Error`][anyhow]
/// that uses a marker type to separate error domains.
///
/// Note that `ContextError` does not implement [`std::error::Error`],
/// because it *does* implement `From<E> where E: Error`
/// (so you can propagate regular errors using `?`),
/// and that would conflict with the blanket `From<T> for T`.
/// Similarly, it does not implement `From<ContextError<D2>>`,
/// forcing you to provide context when crossing error domains.
///
/// [anyhow]: https://docs.rs/anyhow/latest/anyhow/
pub(crate) struct ContextError<D> {
    message: String,
    context: Vec<String>,
    _domain: PhantomData<*const D>,
}

impl<D> ContextError<D> {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            context: vec![],
            _domain: PhantomData,
        }
    }

    pub fn context<D2, C: Into<String>>(mut self, context: C) -> ContextError<D2> {
        self.context.push(context.into());
        ContextError {
            message: self.message,
            context: self.context,
            _domain: PhantomData,
        }
    }
}

pub(crate) trait Context<T> {
    fn context<D2, C: Into<String>>(self, context: C) -> Result<T, ContextError<D2>>;
    fn with_context<D2, C: Into<String>, F: FnOnce() -> C>(
        self,
        context: F,
    ) -> Result<T, ContextError<D2>>;
}

impl<T, D> Context<T> for Result<T, ContextError<D>> {
    fn context<D2, C: Into<String>>(self, context: C) -> Result<T, ContextError<D2>> {
        self.map_err(|e| e.context(context))
    }

    fn with_context<D2, C: Into<String>, F: FnOnce() -> C>(
        self,
        context: F,
    ) -> Result<T, ContextError<D2>> {
        self.map_err(|e| e.context(context()))
    }
}

impl<D> std::fmt::Display for ContextError<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.context.is_empty() {
            self.message.fmt(f)
        } else {
            write!(f, "(")?;
            let mut ctx_iter = self.context.iter().rev();
            write!(f, "{}", ctx_iter.next().expect("checked for empty above"))?;
            for ctx in ctx_iter {
                write!(f, " -> {}", ctx)?;
            }
            write!(f, ") {}", self.message)?;
            Ok(())
        }
    }
}

impl<D> std::fmt::Debug for ContextError<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(std::any::type_name::<Self>())
            .field("message", &self.message)
            .field("context", &self.context)
            .finish()
    }
}

impl<D, E: Error> From<E> for ContextError<D> {
    fn from(error: E) -> Self {
        Self::new(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryFrom;

    struct D1;
    struct D2;

    fn error() -> Result<(), ContextError<D1>> {
        Err(ContextError::new("failure"))
    }

    #[test]
    fn test_basic() {
        let e = ContextError::<D1>::new("message")
            .context::<D2, _>("abc")
            .context::<D1, _>("def");
        assert_eq!("message", e.message);
        assert_eq!(&["abc", "def"], e.context.as_slice());
    }

    #[test]
    fn test_propagation() {
        fn d1() -> Result<(), ContextError<D1>> {
            error().context("abc")?;
            // Test that it can propagate without context.
            error()?;
            Ok(())
        }
        let e = d1().unwrap_err();
        assert_eq!("failure", e.message);
        assert_eq!(&["abc"], e.context.as_slice());
    }

    #[test]
    fn test_propagation_across_domains() {
        fn d2() -> Result<(), ContextError<D2>> {
            // This time the context is required.
            error().context("abc")?;
            Ok(())
        }
        let e = d2().unwrap_err();
        assert_eq!("failure", e.message);
        assert_eq!(&["abc"], e.context.as_slice());
    }

    #[test]
    fn test_propagate_std_error() {
        fn d1() -> Result<(), ContextError<D1>> {
            let _ = u8::try_from(u16::MAX)?;
            unreachable!();
        }
        let _ = d1().unwrap_err();
    }
}
