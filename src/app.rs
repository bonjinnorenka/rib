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

    match cli.command {
        Command::Build(arguments) => {
            let specification = spec::ImageBuildSpec::try_from(*arguments)?;
            let request = spec::BuildRequest::try_from(specification)?;
            let credentials = if request.needs_registry_access()
                || cli.global.docker_config.is_some()
                || !cli.global.credential.is_empty()
            {
                Credentials::load(&cli.global.credential, cli.global.docker_config.as_deref())?
            } else {
                Credentials::default()
            };
            request.run(credentials, progress).await
        }
    }
}
