use super::{
    cli::CargoRibCli,
    config::{CargoMetadata, CargoPackage, parse_config},
    plan::{parse_copies_at, validate_artifact_destination},
};
use clap::Parser;
use std::path::{Path, PathBuf};

use std::fs::File;
use std::io::Read;

use oci_spec::image::{
    ANNOTATION_BASE_IMAGE_DIGEST, ANNOTATION_BASE_IMAGE_NAME, ImageConfiguration, ImageIndex,
    ImageManifest,
};

use super::*;
use crate::digest::blob_path;
use crate::output_target::OutputTarget;
use crate::progress::ProgressMode;
use tempfile::TempDir;

fn archive_entry(path: &Path, name: &str) -> Vec<u8> {
    let mut archive = tar::Archive::new(File::open(path).unwrap());
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().to_string_lossy() == name {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            return bytes;
        }
    }
    panic!("archive contains no entry named {name}");
}

#[test]
fn parses_cargo_arguments_after_separator() {
    let cli = CargoRibCli::try_parse_from([
        "cargo-rib",
        "build",
        "--artifact",
        "target/release/demo",
        "--platform",
        "linux/amd64",
        "--",
        "--release",
        "--locked",
        "--bin",
        "demo",
    ])
    .unwrap();
    let arguments = match cli.command {
        CargoRibCommand::Build(arguments) => *arguments,
    };
    assert_eq!(
        arguments.cargo_args,
        ["--release", "--locked", "--bin", "demo"]
    );
}

#[test]
fn rejects_unknown_metadata_keys() {
    let package = CargoPackage {
        id: "demo 0.1.0".to_string(),
        name: "demo".to_string(),
        manifest_path: PathBuf::from("/tmp/demo/Cargo.toml"),
        metadata: serde_json::json!({"rib": {"artificat": "target/release/demo"}}),
    };
    let error = parse_config(&package).unwrap_err().to_string();
    assert!(error.contains("package.metadata.rib"));
}

#[test]
fn configured_copy_sources_are_relative_to_manifest() {
    let directory = TempDir::new().unwrap();
    let copies = parse_copies_at(
        &[
            "config/default.toml:/app/config.toml".to_string(),
            "/opt/shared:/app/shared".to_string(),
        ],
        directory.path(),
    )
    .unwrap();
    assert_eq!(
        copies[0].specification().source(),
        directory.path().join("config/default.toml")
    );
    assert_eq!(copies[1].specification().source(), Path::new("/opt/shared"));
}

#[test]
fn selects_the_package_containing_the_current_directory() {
    let workspace = TempDir::new().unwrap();
    let first = workspace.path().join("first");
    let second = workspace.path().join("second");
    std::fs::create_dir_all(first.join("src")).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let metadata = CargoMetadata {
        packages: vec![
            CargoPackage {
                id: "first".to_string(),
                name: "first".to_string(),
                manifest_path: first.join("Cargo.toml"),
                metadata: serde_json::json!({}),
            },
            CargoPackage {
                id: "second".to_string(),
                name: "second".to_string(),
                manifest_path: second.join("Cargo.toml"),
                metadata: serde_json::json!({}),
            },
        ],
        workspace_default_members: Vec::new(),
    };
    let selected = select_package(&metadata, &first.join("src")).unwrap();
    assert_eq!(selected.name, "first");
}

#[test]
fn cli_cmd_overrides_configured_cmd() {
    let project = TempDir::new().unwrap();
    let package = CargoPackage {
        id: "demo".to_string(),
        name: "demo".to_string(),
        manifest_path: project.path().join("Cargo.toml"),
        metadata: serde_json::json!({
            "rib": {
                "artifact": "target/release/demo",
                "platform": "linux/amd64",
                "from": "scratch",
                "to": ["oci-archive:dist/image.tar"],
                "cmd": "config-cmd"
            }
        }),
    };
    let cli = CargoRibCli::try_parse_from(["cargo-rib", "build", "--cmd", "cli-cmd"]).unwrap();
    let arguments = match cli.command {
        CargoRibCommand::Build(arguments) => *arguments,
    };
    let plan = resolve_plan(&arguments, &package, project.path()).unwrap();
    assert_eq!(plan.image.cmd(), Some(&["cli-cmd".to_string()][..]));
}

#[test]
fn configured_and_cli_env_merge_with_cli_last_wins() {
    let project = TempDir::new().unwrap();
    let package = CargoPackage {
        id: "demo".to_string(),
        name: "demo".to_string(),
        manifest_path: project.path().join("Cargo.toml"),
        metadata: serde_json::json!({
            "rib": {
                "artifact": "target/release/demo",
                "platform": "linux/amd64",
                "from": "scratch",
                "to": ["oci-archive:dist/image.tar"],
                "env": ["A=base", "B=base"]
            }
        }),
    };
    let cli =
        CargoRibCli::try_parse_from(["cargo-rib", "build", "--env", "A=cli", "--env", "C=x=y"])
            .unwrap();
    let arguments = match cli.command {
        CargoRibCommand::Build(arguments) => *arguments,
    };
    let plan = resolve_plan(&arguments, &package, project.path()).unwrap();
    assert_eq!(
        plan.image.envs(),
        &[
            ("A".to_string(), "cli".to_string()),
            ("B".to_string(), "base".to_string()),
            ("C".to_string(), "x=y".to_string()),
        ]
    );
}

#[test]
fn configured_argv_accepts_arrays_and_quoted_lines() {
    let project = TempDir::new().unwrap();
    let package = CargoPackage {
        id: "demo".to_string(),
        name: "demo".to_string(),
        manifest_path: project.path().join("Cargo.toml"),
        metadata: serde_json::json!({
            "rib": {
                "artifact": "target/release/demo",
                "platform": "linux/amd64",
                "from": "scratch",
                "to": ["oci-archive:dist/image.tar"],
                "entrypoint": ["/bin/sh", "-c", "echo hello world"],
                "cmd": "--title 'two words'"
            }
        }),
    };
    let cli = CargoRibCli::try_parse_from(["cargo-rib", "build"]).unwrap();
    let arguments = match cli.command {
        CargoRibCommand::Build(arguments) => *arguments,
    };
    let plan = resolve_plan(&arguments, &package, project.path()).unwrap();

    assert_eq!(
        plan.image.entrypoint(),
        Some(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hello world".to_string()
            ][..]
        )
    );
    assert_eq!(
        plan.image.cmd(),
        Some(&["--title".to_string(), "two words".to_string()][..])
    );
}

#[test]
fn validates_artifact_destination() {
    assert!(validate_artifact_destination("/usr/local/bin/demo").is_ok());
    assert!(validate_artifact_destination("usr/local/bin/demo").is_err());
    assert!(validate_artifact_destination("/usr/local/bin/").is_err());
}

#[test]
fn configured_and_cli_copies_precede_the_artifact() {
    let project = TempDir::new().unwrap();
    let package = CargoPackage {
        id: "demo".to_string(),
        name: "demo".to_string(),
        manifest_path: project.path().join("Cargo.toml"),
        metadata: serde_json::json!({
            "rib": {
                "artifact": "target/release/demo",
                "platform": "linux/amd64",
                "from": "scratch",
                "to": ["oci-archive:dist/image.tar"],
                "copies": ["config.toml:/app/config.toml"]
            }
        }),
    };
    let cli = CargoRibCli::try_parse_from(["cargo-rib", "build", "--copy", "assets:/app/assets/"])
        .unwrap();
    let arguments = match cli.command {
        CargoRibCommand::Build(arguments) => *arguments,
    };
    let plan = resolve_plan(&arguments, &package, project.path()).unwrap();
    let copies = plan.image.copies();

    assert_eq!(copies.len(), 3);
    assert_eq!(copies[0].description(), "config.toml:/app/config.toml");
    assert_eq!(copies[1].description(), "assets:/app/assets/");
    assert!(copies[2].description().starts_with("artifact "));
    assert_eq!(copies[2].specification().mode(), Some(0o755));
    assert_eq!(copies[2].specification().destination(), "/app/demo");
}

#[tokio::test]
async fn cargo_plan_builds_the_explicit_configured_artifact() {
    let project = TempDir::new().unwrap();
    std::fs::create_dir(project.path().join("src")).unwrap();
    std::fs::write(
        project.path().join("Cargo.toml"),
        r#"
[package]
name = "cargo-rib-fixture"
version = "0.1.0"
edition = "2024"

[package.metadata.rib]
artifact = "target/debug/cargo-rib-fixture"
platform = "linux/amd64"
from = "scratch"
to = ["oci-archive:dist/image.tar"]
destination = "/usr/local/bin/fixture"
env = ["APP_MODE=production"]
cargo-args = ["--offline"]
"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("src/main.rs"),
        "fn main() { println!(\"fixture\"); }\n",
    )
    .unwrap();

    let cargo = cargo_executable();
    let metadata = read_metadata(&cargo, project.path()).await.unwrap();
    let package = select_package(&metadata, project.path()).unwrap();
    let cli = CargoRibCli::try_parse_from([
        "cargo-rib",
        "build",
        "--progress",
        "quiet",
        "--env",
        "RUST_LOG=info",
    ])
    .unwrap();
    let arguments = match cli.command {
        CargoRibCommand::Build(arguments) => *arguments,
    };
    let plan = resolve_plan(&arguments, package, project.path()).unwrap();

    run_cargo_build(&cargo, &plan, &Progress::new(ProgressMode::Quiet))
        .await
        .unwrap();
    validate_artifact(&plan.artifact).unwrap();
    assert!(plan.artifact.ends_with("target/debug/cargo-rib-fixture"));

    std::fs::create_dir(project.path().join("dist")).unwrap();
    plan.image
        .run(Credentials::default(), Progress::new(ProgressMode::Quiet))
        .await
        .unwrap();
    let archive = project.path().join("dist/image.tar");
    assert!(archive.is_file());
    assert!(std::fs::metadata(&archive).unwrap().len() > 0);

    let index: ImageIndex = serde_json::from_slice(&archive_entry(&archive, "index.json")).unwrap();
    let manifest_descriptor = &index.manifests()[0];
    let manifest: ImageManifest = serde_json::from_slice(&archive_entry(
        &archive,
        &blob_path(manifest_descriptor.digest()),
    ))
    .unwrap();
    assert_eq!(manifest.layers().len(), 1);
    let annotations = manifest.annotations().as_ref().unwrap();
    assert!(!annotations.contains_key(ANNOTATION_BASE_IMAGE_NAME));
    assert!(!annotations.contains_key(ANNOTATION_BASE_IMAGE_DIGEST));

    let config: ImageConfiguration = serde_json::from_slice(&archive_entry(
        &archive,
        &blob_path(manifest.config().digest()),
    ))
    .unwrap();
    assert_eq!(config.rootfs().diff_ids().len(), 1);
    assert_eq!(config.history().as_ref().unwrap().len(), 1);
    assert_eq!(
        config.config().as_ref().unwrap().entrypoint().as_ref(),
        Some(&vec!["/usr/local/bin/fixture".to_string()])
    );
    assert_eq!(
        config.config().as_ref().unwrap().env().as_ref(),
        Some(&vec![
            "APP_MODE=production".to_string(),
            "RUST_LOG=info".to_string(),
        ])
    );
}

#[test]
fn explicit_boolean_values_override_metadata_in_both_directions() {
    let project = TempDir::new().unwrap();
    for configured in [false, true] {
        let package = CargoPackage {
            id: "demo".into(),
            name: "demo".into(),
            manifest_path: project.path().join("Cargo.toml"),
            metadata: serde_json::json!({"rib": {
                "artifact": "target/debug/demo", "platform": "linux/amd64", "from": "source.test/base:v1",
                "to": ["registry:target.test/app:v1"], "cache": configured, "keep-cmd": configured,
                "from-plain-http": configured, "from-skip-tls": configured,
                "to-plain-http": configured, "to-skip-tls": configured,
                "cache-path": "cache", "read-timeout": 12, "connect-timeout": 34, "max-attempts": 2
            }}),
        };
        for explicit in [None, Some(false), Some(true)] {
            let mut args = vec!["cargo-rib".to_owned(), "build".to_owned()];
            if let Some(value) = explicit {
                for flag in [
                    "cache",
                    "keep-cmd",
                    "from-plain-http",
                    "from-skip-tls",
                    "to-plain-http",
                    "to-skip-tls",
                ] {
                    args.push(format!("--{flag}={value}"));
                }
            }
            let cli = CargoRibCli::try_parse_from(args).unwrap();
            let CargoRibCommand::Build(arguments) = cli.command;
            let plan = resolve_plan(&arguments, &package, project.path()).unwrap();
            let expected = explicit.unwrap_or(configured);
            assert_eq!(plan.image.cache().enable, expected);
            assert_eq!(
                plan.image.cache().cache_path.as_deref(),
                Some(Path::new("cache"))
            );
            assert_eq!(plan.image.keep_cmd(), expected);
            let (source, target) = plan.image.transport();
            assert_eq!(source.skip_tls_verify, expected);
            assert_eq!(target.skip_tls_verify, expected);
            assert_eq!(!source.plain_http_hosts.is_empty(), expected);
            assert_eq!(!target.plain_http_hosts.is_empty(), expected);
            assert_eq!(source.read_timeout.as_secs(), 12);
            assert_eq!(target.connect_timeout.as_secs(), 34);
            assert_eq!(target.max_attempts, 2);
        }
    }
}

#[test]
fn cli_to_replaces_configured_targets_instead_of_appending() {
    let project = TempDir::new().unwrap();
    let package = CargoPackage {
        id: "demo".into(),
        name: "demo".into(),
        manifest_path: project.path().join("Cargo.toml"),
        metadata: serde_json::json!({
            "rib": {
                "artifact": "target/release/demo",
                "platform": "linux/amd64",
                "from": "scratch",
                "to": [
                    "registry:ghcr.io/example/demo:latest",
                    "registry:ghcr.io/example/demo:0.1.0"
                ]
            }
        }),
    };
    let cli =
        CargoRibCli::try_parse_from(["cargo-rib", "build", "--to", "oci-archive:dist/local.tar"])
            .unwrap();
    let CargoRibCommand::Build(arguments) = cli.command;
    let plan = resolve_plan(&arguments, &package, project.path()).unwrap();

    assert_eq!(
        plan.image.targets(),
        &[OutputTarget::OciArchive {
            path: PathBuf::from("dist/local.tar"),
            tag: None,
        }]
    );
    assert!(!plan.image.needs_registry_access());
}

#[test]
fn cli_multiple_to_flags_preserve_multi_output_when_replacing_config() {
    let project = TempDir::new().unwrap();
    let package = CargoPackage {
        id: "demo".into(),
        name: "demo".into(),
        manifest_path: project.path().join("Cargo.toml"),
        metadata: serde_json::json!({
            "rib": {
                "artifact": "target/release/demo",
                "platform": "linux/amd64",
                "from": "scratch",
                "to": ["registry:ghcr.io/example/demo:latest"]
            }
        }),
    };
    let cli = CargoRibCli::try_parse_from([
        "cargo-rib",
        "build",
        "--to",
        "oci-archive:dist/a.tar@v1",
        "--to",
        "docker-archive:dist/b.tar@v1",
    ])
    .unwrap();
    let CargoRibCommand::Build(arguments) = cli.command;
    let plan = resolve_plan(&arguments, &package, project.path()).unwrap();

    assert_eq!(
        plan.image.targets(),
        &[
            OutputTarget::OciArchive {
                path: PathBuf::from("dist/a.tar"),
                tag: Some("v1".to_string()),
            },
            OutputTarget::DockerArchive {
                path: PathBuf::from("dist/b.tar"),
                tag: Some("v1".to_string()),
            },
        ]
    );
}

#[test]
fn local_only_rejects_configured_registry_target_before_execution() {
    let project = TempDir::new().unwrap();
    let package = CargoPackage {
        id: "demo".into(),
        name: "demo".into(),
        manifest_path: project.path().join("Cargo.toml"),
        metadata: serde_json::json!({
            "rib": {
                "artifact": "target/release/demo",
                "platform": "linux/amd64",
                "from": "scratch",
                "to": ["registry:ghcr.io/example/demo:latest"]
            }
        }),
    };
    let cli = CargoRibCli::try_parse_from(["cargo-rib", "build", "--local-only"]).unwrap();
    let CargoRibCommand::Build(arguments) = cli.command;
    let error = resolve_plan(&arguments, &package, project.path())
        .err()
        .expect("--local-only must reject registry target")
        .to_string();
    assert!(error.contains("--local-only"), "got: {error}");
    assert!(
        error.contains("ghcr.io/example/demo:latest"),
        "got: {error}"
    );
}

#[test]
fn local_only_allows_oci_archive_override_and_multiple_local_outputs() {
    let project = TempDir::new().unwrap();
    let package = CargoPackage {
        id: "demo".into(),
        name: "demo".into(),
        manifest_path: project.path().join("Cargo.toml"),
        metadata: serde_json::json!({
            "rib": {
                "artifact": "target/release/demo",
                "platform": "linux/amd64",
                "from": "scratch",
                "to": ["registry:ghcr.io/example/demo:latest"]
            }
        }),
    };
    let cli = CargoRibCli::try_parse_from([
        "cargo-rib",
        "build",
        "--local-only",
        "--to",
        "oci-archive:dist/a.tar",
        "--to",
        "docker-archive:dist/b.tar",
    ])
    .unwrap();
    let CargoRibCommand::Build(arguments) = cli.command;
    let plan = resolve_plan(&arguments, &package, project.path()).unwrap();
    assert!(plan.image.local_only());
    assert_eq!(plan.image.targets().len(), 2);
}
