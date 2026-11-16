use std::collections::HashSet;
use std::fs;
use std::io::Write;

use crate::builder::copy::{
    CopySpec, Owner, join_posix, resolve_targets_with_roots, strip_leading_slash,
};
use crate::builder::writers::{HashingWriter, SplitWriter};
use crate::cancellable_io::CancellableWriter;
use crate::image::layer::Layer;
use crate::safe_fs::{CopyRoot, OpenedDir, OpenedSource};
use crate::tar_io::{EntryData, write_entry};
use anyhow::{Context, Result};
use flate2::Compression;
use flate2::write::GzEncoder;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
pub fn build_copy_layer(spec: &CopySpec) -> Result<Layer> {
    build_copy_layer_with_roots(spec, &[], true, CancellationToken::new())
}

/// Build a deterministic layer while optionally retaining its uncompressed tar
#[allow(dead_code)]
pub(crate) fn build_copy_layer_with_options(
    spec: &CopySpec,
    retain_uncompressed: bool,
    cancellation: CancellationToken,
) -> Result<Layer> {
    build_copy_layer_with_roots(spec, &[], retain_uncompressed, cancellation)
}

pub(crate) fn build_copy_layer_with_roots(
    spec: &CopySpec,
    copy_roots: &[CopyRoot],
    retain_uncompressed: bool,
    cancellation: CancellationToken,
) -> Result<Layer> {
    let tmpdir = tempfile::tempdir().context("creating layer tempdir")?;
    let compressed_path = tmpdir.path().join("layer.tar.gz");
    let compressed_file = fs::File::create(&compressed_path)
        .with_context(|| format!("creating {}", compressed_path.display()))?;
    let uncompressed_path = retain_uncompressed.then(|| tmpdir.path().join("layer.tar"));
    let uncompressed_writer: Box<dyn Write> = match &uncompressed_path {
        Some(path) => Box::new(
            fs::File::create(path).with_context(|| format!("creating {}", path.display()))?,
        ),
        None => Box::new(std::io::sink()),
    };

    let compressed_hashing_writer = HashingWriter::new(compressed_file);
    let gz = GzEncoder::new(compressed_hashing_writer, Compression::fast());
    let uncompressed_hashing_writer = HashingWriter::new(uncompressed_writer);
    let split_writer = SplitWriter::new(uncompressed_hashing_writer, gz);
    let cancellable_writer = CancellableWriter::new(split_writer, cancellation, "layer build");
    let mut builder = tar::Builder::new(cancellable_writer);

    write_to_tar(&mut builder, spec, copy_roots)?;

    // Unwind. into_inner() calls finish() which writes tar trailer blocks
    let cancellable_writer = builder.into_inner().context("finalizing tar")?;
    let split_writer = cancellable_writer.into_inner();
    let (uncompressed_hashing_writer, gz) = split_writer.into_inner();
    let (diff_id, uncompressed_size) = uncompressed_hashing_writer.finalize();
    let compressed_hashing_writer = gz.finish().context("finalizing gzip")?;
    let (digest, size) = compressed_hashing_writer.finalize();

    Layer::from_built_tar(
        tmpdir,
        diff_id,
        digest,
        uncompressed_size,
        size,
        retain_uncompressed,
    )
}

fn write_dir_entries_fd<W: Write>(
    builder: &mut tar::Builder<W>,
    dir: &OpenedDir,
    dst_root: &str,
    spec: &CopySpec,
    seen: &mut HashSet<String>,
) -> Result<()> {
    let key = strip_leading_slash(dst_root)
        .trim_end_matches('/')
        .to_string();
    if !key.is_empty() && seen.insert(key) {
        write_entry(
            builder,
            &format!("{}/", dst_root.trim_end_matches('/')),
            EntryData::Dir,
            None,
            spec.chown(),
        )?;
    }

    for name in dir.child_names_sorted()? {
        let name_str = name.to_str().with_context(|| {
            format!(
                "source path is not valid UTF-8: {}",
                std::path::Path::new(&name).display()
            )
        })?;
        let dst_path = join_posix(dst_root, name_str);
        match dir.open_child(&name)? {
            OpenedSource::Dir(subdir) => {
                write_dir_entries_fd(builder, &subdir, &dst_path, spec, seen)?;
            }
            OpenedSource::File(mut file) => {
                write_entry(
                    builder,
                    &dst_path,
                    EntryData::File(&mut file),
                    spec.mode(),
                    spec.chown(),
                )?;
            }
        }
    }
    Ok(())
}

/// Walk `dst` left-to-right and append a directory entry for each segment
/// except the last. So `/app/sub/file.bin` produces `app/` and `app/sub/`
/// Skips entries already in `seen` to avoid duplicates
fn ensure_parent_dirs<W: Write>(
    builder: &mut tar::Builder<W>,
    dst: &str,
    seen: &mut HashSet<String>,
    chown: Option<Owner>,
) -> Result<()> {
    let stripped = strip_leading_slash(dst);
    // Drop the final segment — it'll be written as the file/dir itself
    let parts: Vec<&str> = stripped
        .trim_end_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() <= 1 {
        return Ok(()); // file at root, no parents to make
    }
    let mut path = String::new();
    for part in &parts[..parts.len() - 1] {
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(part);
        if seen.insert(path.clone()) {
            write_entry(builder, &format!("{path}/"), EntryData::Dir, None, chown)?;
        }
    }
    Ok(())
}

/// One concrete (src, dst-in-image) pair after globbing and dst-resolution
/// Created from a CopySpec by `resolve_targets_with_roots`
fn write_to_tar<W: Write>(
    builder: &mut tar::Builder<W>,
    spec: &CopySpec,
    copy_roots: &[CopyRoot],
) -> Result<()> {
    let entries = resolve_targets_with_roots(spec, copy_roots)?;

    let mut dirs_written: HashSet<String> = HashSet::new();

    for entry in entries {
        match entry.source {
            OpenedSource::Dir(dir) => {
                ensure_parent_dirs(builder, &entry.dst, &mut dirs_written, spec.chown())?;
                // Directory itself is the dst — write it as a directory entry,
                // then walk its CONTENTS into it via pinned directory FDs
                write_dir_entries_fd(builder, &dir, &entry.dst, spec, &mut dirs_written)?;
            }
            OpenedSource::File(mut file) => {
                ensure_parent_dirs(builder, &entry.dst, &mut dirs_written, spec.chown())?;
                write_entry(
                    builder,
                    &entry.dst,
                    EntryData::File(&mut file),
                    spec.mode(),
                    spec.chown(),
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempfile::TempDir;

    fn write_tmp(dir: &TempDir, name: &str, content: &[u8]) -> std::path::PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    fn make_tree() -> TempDir {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"b").unwrap();
        std::fs::write(dir.path().join("ignore.md"), b"i").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/c.txt"), b"c").unwrap();
        dir
    }

    fn paths_in_layer(layer: &Layer) -> Vec<String> {
        let mut f = layer.open_uncompressed().unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut bytes).unwrap();
        let mut archive = tar::Archive::new(bytes.as_slice());
        archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn dst_with_trailing_slash_keeps_basename() {
        // file -> /app/  →  /app/<basename>
        let dir = make_tree();
        let spec = CopySpec::from_str(&format!("{}/a.txt:/app/", dir.path().display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();
        let paths = paths_in_layer(&layer);
        assert!(paths.contains(&"app/a.txt".to_string()), "got {paths:?}");
        // No "app/" without basename means dst was treated as a directory
        assert!(!paths.contains(&"app".to_string()));
    }

    #[test]
    fn dst_without_trailing_slash_is_exact_filename() {
        // file -> /app/foo.txt  →  /app/foo.txt (renamed)
        let dir = make_tree();
        let spec =
            CopySpec::from_str(&format!("{}/a.txt:/app/foo.txt", dir.path().display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();
        let paths = paths_in_layer(&layer);
        assert!(paths.contains(&"app/foo.txt".to_string()), "got {paths:?}");
    }

    #[test]
    fn directory_source_copies_contents_not_itself() {
        // Docker rule: COPY mydir/ /app/ puts contents of mydir into /app/,
        // it does NOT create /app/mydir/
        let dir = make_tree();
        let spec = CopySpec::from_str(&format!("{}:/app/", dir.path().display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();
        let paths = paths_in_layer(&layer);

        // Files end up directly in /app/, not in /app/<basename of dir>/
        assert!(paths.contains(&"app/a.txt".to_string()), "got {paths:?}");
        assert!(paths.contains(&"app/b.txt".to_string()));
        assert!(paths.contains(&"app/sub/c.txt".to_string()));
        // No nesting under the source dir's name
        let dir_basename = dir
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            !paths
                .iter()
                .any(|p| p.starts_with(&format!("app/{dir_basename}"))),
            "must not nest under source dir name: {paths:?}"
        );
    }

    #[test]
    fn directory_source_copies_contents_to_image_root() {
        let dir = make_tree();
        let spec = CopySpec::from_str(&format!("{}:/", dir.path().display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();
        let paths = paths_in_layer(&layer);

        assert!(paths.contains(&"a.txt".to_string()), "got {paths:?}");
        assert!(paths.contains(&"b.txt".to_string()));
        assert!(paths.contains(&"sub/c.txt".to_string()));
        assert!(
            paths.iter().all(|path| !path.starts_with('/')),
            "tar paths must be relative: {paths:?}"
        );
    }

    fn assert_long_destination(destination: &str) {
        let dir = TempDir::new().unwrap();
        let source = write_tmp(&dir, "payload", b"payload");
        let spec = CopySpec::from_str(&format!("{}:{destination}", source.display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();
        let paths = paths_in_layer(&layer);
        let expected = destination.trim_start_matches('/');

        assert!(
            paths.iter().any(|path| path == expected),
            "missing {expected:?} in {paths:?}"
        );
        assert!(paths.iter().all(|path| !path.starts_with('/')));
    }

    #[test]
    fn supports_gnu_tar_paths_longer_than_100_bytes() {
        let destination = format!("/{}/payload", "a".repeat(101));
        assert!(destination.len() > 100);
        assert_long_destination(&destination);
    }

    #[test]
    fn supports_gnu_tar_paths_longer_than_255_bytes() {
        let component = "segment".repeat(10);
        let destination = format!("/{component}/{component}/{component}/{component}/payload");
        assert!(destination.len() > 255);
        assert_long_destination(&destination);
    }

    #[test]
    fn glob_expands_to_multiple_files() {
        let dir = make_tree();
        let spec = CopySpec::from_str(&format!("{}/*.txt:/app/", dir.path().display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();
        let paths = paths_in_layer(&layer);
        // Both .txt files matched; .md was skipped
        assert!(paths.contains(&"app/a.txt".to_string()), "got {paths:?}");
        assert!(paths.contains(&"app/b.txt".to_string()));
        assert!(!paths.iter().any(|p| p.contains("ignore.md")));
    }

    #[test]
    fn glob_with_no_matches_errors() {
        let dir = TempDir::new().unwrap();
        let spec = CopySpec::from_str(&format!("{}/*.nope:/app/", dir.path().display())).unwrap();
        assert!(build_copy_layer(&spec).is_err());
    }

    #[test]
    fn glob_with_multiple_matches_requires_dir_dst() {
        // `*.txt → /app/foo` (no slash) is ambiguous — Docker rejects this,
        // and so do we. Caller must add a trailing slash to dst
        let dir = make_tree();
        let spec = CopySpec::from_str(&format!("{}/*.txt:/app/foo", dir.path().display())).unwrap();
        let err = build_copy_layer(&spec).unwrap_err();
        assert!(
            format!("{err}").contains("not a directory"),
            "expected 'not a directory' in error, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_source_fails_instead_of_being_silently_skipped() {
        use std::os::unix::fs::symlink;

        let dir = make_tree();
        let link = dir.path().join("link.txt");
        symlink(dir.path().join("a.txt"), &link).unwrap();
        let spec = CopySpec::from_str(&format!("{}:/app/link.txt", link.display())).unwrap();
        let error = build_copy_layer(&spec).unwrap_err();
        assert!(error.to_string().contains("symlink"));
    }

    #[test]
    fn chown_propagates_to_file_and_parent_dirs() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("x"), b"x").unwrap();
        let spec = CopySpec::from_str(&format!(
            "{}/x:/app/bin/x,chown=1000:2000",
            dir.path().display()
        ))
        .unwrap();
        let layer = build_copy_layer(&spec).unwrap();

        let mut f = layer.open_uncompressed().unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut bytes).unwrap();
        let mut archive = tar::Archive::new(bytes.as_slice());
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            assert_eq!(entry.header().uid().unwrap(), 1000);
            assert_eq!(entry.header().gid().unwrap(), 2000);
        }
    }

    #[test]
    fn builds_from_single_file() {
        let dir = TempDir::new().unwrap();
        let src = write_tmp(&dir, "hello.txt", b"hello");
        let spec = CopySpec::from_str(&format!("{}:/app/hello.txt", src.display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();

        assert!(layer.diff_id().to_string().starts_with("sha256:"));
        assert!(
            layer
                .descriptor()
                .digest()
                .to_string()
                .starts_with("sha256:")
        );
        assert!(layer.size() > 0);
        assert!(layer.uncompressed_size() > 0);
    }

    /// The canonical OCI bug: producers that put the gzipped digest into
    /// rootfs.diff_ids. Should never happen here
    #[test]
    fn diff_id_differs_from_digest() {
        let dir = TempDir::new().unwrap();
        let src = write_tmp(&dir, "x.txt", b"some content here");
        let spec = CopySpec::from_str(&format!("{}:/x.txt", src.display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();
        assert_ne!(
            layer.diff_id().to_string(),
            layer.descriptor().digest().to_string(),
            "diff_id (uncompressed) must never equal digest (gzipped)"
        );
    }

    #[test]
    fn skipping_uncompressed_storage_preserves_layer_identity() {
        let dir = TempDir::new().unwrap();
        let source = write_tmp(&dir, "payload", b"payload");
        let spec = CopySpec::from_str(&format!("{}:/payload", source.display())).unwrap();

        let retained =
            build_copy_layer_with_options(&spec, true, CancellationToken::new()).unwrap();
        let discarded =
            build_copy_layer_with_options(&spec, false, CancellationToken::new()).unwrap();

        assert!(retained.open_uncompressed().is_ok());
        assert!(discarded.open_uncompressed().is_err());
        assert!(discarded.compressed_path().is_file());
        assert!(discarded.open_uncompressed().is_err());
        assert_eq!(discarded.diff_id(), retained.diff_id());
        assert_eq!(discarded.descriptor(), retained.descriptor());
        assert_eq!(discarded.uncompressed_size(), retained.uncompressed_size());
    }

    #[test]
    fn cancelled_layer_build_stops_before_writing_data() {
        let dir = TempDir::new().unwrap();
        let source = write_tmp(&dir, "payload", b"payload");
        let spec = CopySpec::from_str(&format!("{}:/payload", source.display())).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = build_copy_layer_with_options(&spec, false, cancellation).unwrap_err();

        assert!(format!("{error:#}").contains("layer build cancelled"));
    }

    #[test]
    fn explicit_mode_is_applied() {
        let dir = TempDir::new().unwrap();
        let src = write_tmp(&dir, "x", b"x");
        let spec = CopySpec::from_str(&format!("{}:/x,mode=0700", src.display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();

        let uncompressed = layer.uncompressed_bytes().unwrap();
        let mut archive = tar::Archive::new(uncompressed.as_slice());
        let entry = archive.entries().unwrap().next().unwrap().unwrap();
        let mode = entry.header().mode().unwrap();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn entries_have_zero_mtime_uid_gid() {
        let dir = TempDir::new().unwrap();
        let src = write_tmp(&dir, "x", b"x");
        let spec = CopySpec::from_str(&format!("{}:/x", src.display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();

        let uncompressed = layer.uncompressed_bytes().unwrap();
        let mut archive = tar::Archive::new(uncompressed.as_slice());
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let h = entry.header();
            assert_eq!(h.mtime().unwrap(), 0);
            assert_eq!(h.uid().unwrap(), 0);
            assert_eq!(h.gid().unwrap(), 0);
        }
    }

    #[test]
    fn directory_walk_is_sorted() {
        let dir = TempDir::new().unwrap();
        // Create out of order to make sure we're not just observing FS order
        std::fs::write(dir.path().join("z.txt"), b"z").unwrap();
        std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
        std::fs::write(dir.path().join("m.txt"), b"m").unwrap();

        let spec = CopySpec::from_str(&format!("{}:/x", dir.path().display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();

        let uncompressed = layer.uncompressed_bytes().unwrap();
        let mut archive = tar::Archive::new(uncompressed.as_slice());
        let order: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.header().entry_type() == tar::EntryType::Regular)
            .map(|e| {
                e.path()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(order, vec!["a.txt", "m.txt", "z.txt"]);
    }

    #[test]
    fn destination_paths_are_stripped_of_leading_slash() {
        // OCI/Docker tar convention: no leading slash on entry paths
        let dir = TempDir::new().unwrap();
        let src = write_tmp(&dir, "x", b"x");
        let spec = CopySpec::from_str(&format!("{}:/usr/local/bin/app", src.display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();

        let uncompressed = layer.uncompressed_bytes().unwrap();
        let mut archive = tar::Archive::new(uncompressed.as_slice());
        let entries: Vec<(String, tar::EntryType)> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let path = e.path().unwrap().to_string_lossy().into_owned();
                (path, e.header().entry_type())
            })
            .collect();
        // Parent directories are materialized in order, then the file itself
        let paths: Vec<&String> = entries.iter().map(|(p, _)| p).collect();
        assert_eq!(
            paths,
            vec!["usr/", "usr/local/", "usr/local/bin/", "usr/local/bin/app"],
            "got {entries:?}"
        );
        // Last entry must be the regular file with the right path
        let last = entries.last().unwrap();
        assert_eq!(last.0, "usr/local/bin/app");
        assert_eq!(last.1, tar::EntryType::Regular);
    }

    /// Parent dirs created when --copy targets nested paths must have sane
    /// permissions (0o755), not the broken "----------" some viewers fall
    /// back to when no directory entry exists at all
    #[test]
    fn parent_directories_have_proper_permissions() {
        let dir = TempDir::new().unwrap();
        let src = write_tmp(&dir, "x", b"x");
        let spec = CopySpec::from_str(&format!("{}:/app/bin/server", src.display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();

        let uncompressed = layer.uncompressed_bytes().unwrap();
        let mut archive = tar::Archive::new(uncompressed.as_slice());
        let dir_entries: Vec<(String, u32)> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.header().entry_type() == tar::EntryType::Directory)
            .map(|e| {
                let p = e.path().unwrap().to_string_lossy().into_owned();
                let m = e.header().mode().unwrap();
                (p, m & 0o777)
            })
            .collect();
        assert_eq!(
            dir_entries.len(),
            2,
            "expected app/ and app/bin/, got {dir_entries:?}"
        );
        for (path, mode) in &dir_entries {
            assert_eq!(*mode, 0o755, "{path} has mode {mode:o}, expected 755");
        }
    }

    /// Ignored by default. Run with: `cargo test smoke_dump_to_tmp -- --ignored --nocapture`
    /// Builds a small layer and writes the gzipped tar to /tmp for inspection
    /// with stock tools (`tar -tzvf`, `gzip -lv`, etc)
    #[test]
    #[ignore]
    fn smoke_dump_to_tmp() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("greeting.txt"), b"hello\n").unwrap();
        std::fs::write(dir.path().join("sub/nested.txt"), b"nested\n").unwrap();

        let spec = CopySpec::from_str(&format!("{}:/app", dir.path().display())).unwrap();
        let layer = build_copy_layer(&spec).unwrap();

        let compressed = layer.compressed_bytes().unwrap();
        std::fs::write("/tmp/rib-smoke.tar.gz", &compressed).unwrap();
        eprintln!("diff_id      = {}", layer.diff_id());
        eprintln!("digest       = {}", layer.descriptor().digest());
        eprintln!("uncompressed = {} bytes", layer.uncompressed_size());
        eprintln!("compressed   = {} bytes", layer.size());
        eprintln!("wrote /tmp/rib-smoke.tar.gz");
    }

    #[test]
    fn copy_root_allows_files_dirs_and_globs_inside_root() {
        let workspace = TempDir::new().unwrap();
        let allowed = workspace.path().join("allowed");
        std::fs::create_dir_all(allowed.join("nested")).unwrap();
        std::fs::write(allowed.join("app.bin"), b"bin").unwrap();
        std::fs::write(allowed.join("nested/cfg.toml"), b"cfg").unwrap();
        let root = CopyRoot::open(&allowed).unwrap();

        let file_spec = CopySpec::from_str(&format!(
            "{}:/app/app.bin",
            allowed.join("app.bin").display()
        ))
        .unwrap();
        let layer = build_copy_layer_with_roots(
            &file_spec,
            std::slice::from_ref(&root),
            true,
            CancellationToken::new(),
        )
        .unwrap();
        assert!(paths_in_layer(&layer).contains(&"app/app.bin".to_string()));

        let glob_spec = CopySpec::from_str(&format!("{}/*.bin:/app/", allowed.display())).unwrap();
        let glob_layer = build_copy_layer_with_roots(
            &glob_spec,
            std::slice::from_ref(&root),
            true,
            CancellationToken::new(),
        )
        .unwrap();
        assert!(paths_in_layer(&glob_layer).contains(&"app/app.bin".to_string()));
    }

    #[test]
    fn copy_root_rejects_outside_paths_and_parent_traversal() {
        let workspace = TempDir::new().unwrap();
        let allowed = workspace.path().join("allowed");
        let secret = workspace.path().join("secret.txt");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::write(&secret, b"top-secret").unwrap();
        let root = CopyRoot::open(&allowed).unwrap();

        let outside_spec =
            CopySpec::from_str(&format!("{}:/app/secret.txt", secret.display())).unwrap();
        assert!(
            build_copy_layer_with_roots(
                &outside_spec,
                std::slice::from_ref(&root),
                false,
                CancellationToken::new()
            )
            .is_err()
        );

        let traversal_spec = CopySpec::from_str(&format!(
            "{}:/app/secret.txt",
            allowed.join("../secret.txt").display()
        ))
        .unwrap();
        assert!(
            build_copy_layer_with_roots(
                &traversal_spec,
                std::slice::from_ref(&root),
                false,
                CancellationToken::new()
            )
            .is_err()
        );

        let glob_escape =
            CopySpec::from_str(&format!("{}/../*.txt:/app/", allowed.display())).unwrap();
        assert!(
            build_copy_layer_with_roots(
                &glob_escape,
                std::slice::from_ref(&root),
                false,
                CancellationToken::new()
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_root_rejects_symlink_escapes_in_parents_and_children() {
        use std::os::unix::fs::symlink;

        let workspace = TempDir::new().unwrap();
        let allowed = workspace.path().join("allowed");
        let outside = workspace.path().join("outside");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"secret").unwrap();

        symlink(&outside, allowed.join("escape_dir")).unwrap();
        symlink(outside.join("secret.txt"), allowed.join("escape_file")).unwrap();
        let root = CopyRoot::open(&allowed).unwrap();

        // Intermediate symlink component
        let via_parent = CopySpec::from_str(&format!(
            "{}:/app/secret.txt",
            allowed.join("escape_dir/secret.txt").display()
        ))
        .unwrap();
        assert!(
            build_copy_layer_with_roots(
                &via_parent,
                std::slice::from_ref(&root),
                false,
                CancellationToken::new()
            )
            .is_err()
        );

        // Leaf symlink inside root
        let via_leaf = CopySpec::from_str(&format!(
            "{}:/app/secret.txt",
            allowed.join("escape_file").display()
        ))
        .unwrap();
        assert!(
            build_copy_layer_with_roots(
                &via_leaf,
                std::slice::from_ref(&root),
                false,
                CancellationToken::new()
            )
            .is_err()
        );

        // Directory walk encountering symlink inside allowed root
        let dir_walk = CopySpec::from_str(&format!("{}:/app/", allowed.display())).unwrap();
        assert!(
            build_copy_layer_with_roots(
                &dir_walk,
                std::slice::from_ref(&root),
                false,
                CancellationToken::new()
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn standalone_copy_rejects_fifo_without_blocking() {
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("pipe");
        let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // Create a named pipe (FIFO) — opening without O_NONBLOCK would hang.
        assert_eq!(unsafe { libc_mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let spec = CopySpec::from_str(&format!("{}:/app/pipe", fifo.display())).unwrap();
        let err = build_copy_layer(&spec).unwrap_err().to_string();
        assert!(err.contains("special file"), "got: {err}");
    }

    #[cfg(unix)]
    unsafe extern "C" {
        #[link_name = "mkfifo"]
        fn libc_mkfifo(pathname: *const std::ffi::c_char, mode: u32) -> i32;
    }
}
