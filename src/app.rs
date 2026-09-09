mod build;
mod push;
pub(crate) mod runtime;
pub(crate) mod spec;

use anyhow::Result;

use crate::auth::Credentials;
use crate::cli::{Command, parse};
use crate::progress::Progress;

pub async fn run() -> Result<()> {
    let cli = parse();
    let progress = Progress::new(cli.global.progress);
    runtime::init_tracing(&progress);
    let credentials =
        Credentials::load(&cli.global.credential, cli.global.docker_config.as_deref())?;

    match cli.command {
        Command::Build(arguments) => {
            let specification = spec::ImageBuildSpec::try_from(*arguments)?;
            spec::BuildRequest::try_from(specification)?
                .run(credentials, progress)
                .await
        }
    }
}
