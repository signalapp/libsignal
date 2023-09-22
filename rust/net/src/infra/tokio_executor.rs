// This file contains code from the `hyper-util` library,
// used under the MIT License:
// https://github.com/hyperium/hyper-util/blob/e25557cb7acf46719d711150fd834014bbc7cb58/LICENSE

use hyper::rt::Executor;
use std::future::Future;

/// Future executor that utilises `tokio` threads.
#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct TokioExecutor {}

impl<Fut> Executor<Fut> for TokioExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::spawn(fut);
    }
}

impl TokioExecutor {
    /// Create new executor that relies on [`tokio::spawn`] to execute futures.
    pub fn new() -> Self {
        Self {}
    }
}
