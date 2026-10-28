use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Runs a future that never waits to its end: the doubles answer at once, so
/// a use case driven on them needs no runtime.
///
/// # Panics
///
/// Panics when the future waits, which a double must never cause.
pub fn complete<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("a future driven on databse waited"),
    }
}
