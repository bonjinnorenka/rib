#![cfg_attr(not(test), warn(clippy::unwrap_used))]
#![doc = include_str!("../README.crates.io.md")]

mod app;
mod archive;
mod auth;
mod blob;
mod builder;
mod cache;
mod cancellable_io;
mod cargo_integration;
mod cli;
mod digest;
mod image;
mod limits;
mod output_target;
mod progress;
mod registry;
mod safe_fs;
mod tar_io;

use anyhow::Result;
use app::runtime::run_until_interrupted;

#[doc(hidden)]
pub async fn run() -> Result<()> {
    run_until_interrupted(app::run()).await
}

#[doc(hidden)]
pub async fn run_cargo() -> Result<()> {
    run_until_interrupted(cargo_integration::run()).await
}
