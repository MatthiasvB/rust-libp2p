#![doc = include_str!("../README.md")]

mod behaviour;
mod control;
mod handler;
mod shared;
mod upgrade;

pub use behaviour::{AlreadyRegistered, Behaviour, Config};
pub use control::{Control, IncomingStreams, OpenStreamError};
