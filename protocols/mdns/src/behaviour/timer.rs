// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::time::{Duration, Instant};

/// Simple wrapper for the different type of timers
#[derive(Debug)]
#[cfg(feature = "tokio")]
pub struct Timer<T> {
    inner: T,
}

/// Builder interface to homogenize the different implementations
#[allow(unreachable_pub)] // Users should not depend on this.
pub trait Builder: Send + Unpin + 'static {
    /// Creates a timer that emits an event once at the given time instant.
    fn at(instant: Instant) -> Self;

    /// Creates a timer that emits events periodically.
    fn interval(duration: Duration) -> Self;

    /// Creates a timer that emits events periodically, starting at start.
    fn interval_at(start: Instant, duration: Duration) -> Self;
}

#[cfg(feature = "tokio")]
pub(crate) mod tokio {
    use std::{
        pin::Pin,
        task::{Context, Poll, ready},
    };

    use ::tokio::time::{self, Instant as TokioInstant, Interval, MissedTickBehavior, Sleep};
    use futures::Stream;

    use super::*;

    /// Tokio wrapper
    pub(crate) type TokioTimer = Timer<Inner>;

    #[derive(Debug)]
    pub enum Inner {
        /// Fires once at its deadline and is `None` after that.
        Once(Option<Pin<Box<Sleep>>>),
        Interval(Interval),
    }

    impl Builder for TokioTimer {
        fn at(instant: Instant) -> Self {
            let sleep = time::sleep_until(TokioInstant::from_std(instant));
            Self {
                inner: Inner::Once(Some(Box::pin(sleep))),
            }
        }

        fn interval(duration: Duration) -> Self {
            let mut inner = time::interval_at(TokioInstant::now() + duration, duration);
            inner.set_missed_tick_behavior(MissedTickBehavior::Skip);
            Self {
                inner: Inner::Interval(inner),
            }
        }

        fn interval_at(start: Instant, duration: Duration) -> Self {
            let mut inner = time::interval_at(TokioInstant::from_std(start), duration);
            inner.set_missed_tick_behavior(MissedTickBehavior::Skip);
            Self {
                inner: Inner::Interval(inner),
            }
        }
    }

    impl Stream for TokioTimer {
        type Item = TokioInstant;

        /// A one-shot timer stays pending after it fired.
        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match &mut self.inner {
                Inner::Once(sleep) => {
                    let Some(pending) = sleep else {
                        return Poll::Pending;
                    };
                    ready!(pending.as_mut().poll(cx));
                    let deadline = pending.deadline();
                    *sleep = None;
                    Poll::Ready(Some(deadline))
                }
                Inner::Interval(interval) => interval.poll_tick(cx).map(Some),
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, None)
        }
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use std::time::Duration;

    use futures::StreamExt as _;
    use tokio::time::{self, Instant};

    use super::{Builder as _, tokio::TokioTimer};

    #[tokio::test(start_paused = true)]
    async fn one_shot_polled_late_fires_once() {
        let mut timer = TokioTimer::at(Instant::now().into_std());

        time::advance(Duration::from_secs(3600)).await;

        assert!(timer.next().await.is_some());
        let ten_years = Duration::from_secs(10 * 365 * 24 * 60 * 60);
        assert!(time::timeout(ten_years, timer.next()).await.is_err());
    }
}
