use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::safe_fs::{
    CopyRoot, OpenedSource, check_glob_within_copy_roots, check_within_copy_roots_lexical,
    open_copy_source,
};
pub use crate::tar_io::Owner;

#[derive(Debug, Clone)]
pub struct CopySpec {
    /// Source as written by the user. May be a glob
    src: CopySource,
    /// Destination path inside the image
    dst: String,
    /// Optional file mode override (octal)
    mode: Option<u32>,
    /// Optional ownership
    chown: Option<Owner>,
}

#[derive(Debug, Clone)]
enum CopySource {
    Path(PathBuf),
    Glob(String),
}

#[derive(Debug)]
pub struct ResolvedEntry {
    #[cfg_attr(not(test), allow(dead_code))]
    pub src: PathBuf,
    pub source: OpenedSource,
    /// Path inside the image for this entry. Always without leading slash,
    /// always normalized. For directories, this is the root under which the
    /// directory's contents are placed (Docker semantics: contents, not the
    /// directory itself)
    pub dst: String,
}

impl FromStr for CopySpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // Skip the drive-letter colon in Windows paths, but retain the colon
        // separating the image destination from the source.
        let start = if s.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && s.as_bytes().get(1) == Some(&b':')
            && s[2..]
                .split(',')
                .next()
                .is_some_and(|path| path.contains(':'))
        {
            2
        } else {
            0
        };
        let separator = s[start..]
            .find(':')
            .map(|index| index + start)
            .ok_or_else(|| anyhow!("invalid COPY directive, expected <src>:<dst>[,opts]: {s}"))?;
        let (src, rest) = (&s[..separator], &s[separator + 1..]);
        if src.is_empty() {
            bail!("COPY source is empty: {s}");
        }

        // Destination paths containing commas are intentionally unsupported
        let (dst_raw, opts_raw) = match rest.split_once(',') {
            Some((d, o)) => (d, Some(o)),
            None => (rest, None),
        };
        if dst_raw.is_empty() {
            bail!("COPY destination is empty: {s}");
        }
        validate_image_destination(dst_raw)?;
        let dst = dst_raw.replace('\\', "/");

        let mut mode: Option<u32> = None;
        let mut chown: Option<Owner> = None;
        if let Some(opts) = opts_raw {
            for kv in opts.split(',') {
                let kv = kv.trim();
                if kv.is_empty() {
                    continue;
                }
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| anyhow!("invalid COPY option {kv:?}, expected key=value"))?;
                match k {
                    "mode" | "chmod" => {
                        let parsed = u32::from_str_radix(v, 8)
                            .with_context(|| format!("bad mode {v:?} (octal expected)"))?;
                        if parsed > 0o7777 {
                            bail!("bad mode {v:?} (must fit in 07777)");
                        }
                        mode = Some(parsed);
                    }
                    "chown" | "owner" => {
                        chown = Some(parse_owner(v)?);
                    }
                    other => bail!("unknown COPY option {other:?} (valid: mode, chown)"),
                }
            }
        }

        Ok(Self {
            src: if has_glob_meta(src) {
                CopySource::Glob(src.to_string())
            } else {
                CopySource::Path(PathBuf::from(src))
            },
            dst,
            mode,
            chown,
        })
    }
}

impl CopySpec {
    pub(crate) fn executable(src: &std::path::Path, dst: &str) -> Result<Self> {
        validate_image_destination(dst)?;
        Ok(Self {
            src: CopySource::Path(src.to_path_buf()),
            dst: dst.replace('\\', "/"),
            mode: Some(0o755),
            chown: None,
        })
    }
    pub fn mode(&self) -> Option<u32> {
        self.mode
    }
    pub fn chown(&self) -> Option<Owner> {
        self.chown
    }
    pub fn destination(&self) -> &str {
        &self.dst
    }
    pub fn destination_is_directory(&self) -> bool {
        self.dst.ends_with('/')
    }
    pub fn source(&self) -> &Path {
        match &self.src {
            CopySource::Path(path) => path,
            CopySource::Glob(pattern) => Path::new(pattern),
        }
    }

    pub fn resolve_relative_to(&mut self, base: &Path) -> Result<()> {
        if self.source().is_absolute() {
            return Ok(());
        }
        match &mut self.src {
            CopySource::Path(path) => *path = base.join(&*path),
            CopySource::Glob(pattern) => {
                let base = base
                    .to_str()
                    .context("glob base directory is not valid UTF-8")?;
                // A literal workspace directory may itself contain glob syntax.
                *pattern = Path::new(&glob::Pattern::escape(base))
                    .join(&*pattern)
                    .to_str()
                    .context("glob path is not valid UTF-8")?
                    .to_owned();
            }
        }
        Ok(())
    }
}

fn validate_image_destination(dst: &str) -> Result<()> {
    if dst.contains('\0') {
        bail!("image destination contains a NUL byte");
    }
    let normalized = dst.replace('\\', "/");
    let relative = normalized.trim_matches('/');
    if relative.is_empty() {
        return Ok(());
    }
    for component in relative.split('/') {
        if component == "." || component == ".." {
            bail!("image destination must not contain {component:?}: {dst:?}");
        }
        if component.is_empty() {
            bail!("image destination contains an empty path component: {dst:?}");
        }
    }
    Ok(())
}

fn parse_owner(s: &str) -> Result<Owner> {
    let (uid_s, gid_s) = match s.split_once(':') {
        Some((u, g)) => (u, g),
        None => (s, "0"),
    };
    let uid = uid_s
        .parse::<u64>()
        .with_context(|| format!("bad chown uid {uid_s:?}"))?;
    let gid = gid_s
        .parse::<u64>()
        .with_context(|| format!("bad chown gid {gid_s:?}"))?;
    Ok(Owner { uid, gid })
}

pub fn has_glob_meta(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

pub fn strip_leading_slash(path: &str) -> &str {
    path.trim_start_matches('/')
}

fn strip_trailing_slash(path: &str) -> &str {
    path.trim_end_matches('/')
}

fn normalize_image_path(path: &str) -> String {
    path.trim_start_matches('/').replace('\\', "/")
}

pub fn join_posix(base: &str, suffix: &str) -> String {
    let base = base.trim_end_matches('/');
    let suffix = suffix.trim_start_matches('/').replace('\\', "/");
    match (base.is_empty(), suffix.is_empty()) {
        (true, _) => suffix,
        (_, true) => base.to_string(),
        (false, false) => format!("{base}/{suffix}"),
    }
}

/// Pre-validate a COPY spec against `copy_roots` before files like built
/// artifacts necessarily exist on disk.
pub fn validate_spec_within_roots(spec: &CopySpec, copy_roots: &[CopyRoot]) -> Result<()> {
    if copy_roots.is_empty() {
        return Ok(());
    }
    match &spec.src {
        CopySource::Path(path) => check_within_copy_roots_lexical(path, copy_roots),
        CopySource::Glob(pattern) => check_glob_within_copy_roots(pattern, copy_roots),
    }
}

/// Expand glob, then open and validate each matched src path without TOCTOU.
#[cfg(test)]
pub fn resolve_targets(spec: &CopySpec) -> Result<Vec<ResolvedEntry>> {
    resolve_targets_with_roots(spec, &[])
}

pub fn resolve_targets_with_roots(
    spec: &CopySpec,
    copy_roots: &[CopyRoot],
) -> Result<Vec<ResolvedEntry>> {
    let matches: Vec<PathBuf> = if let CopySource::Glob(pattern) = &spec.src {
        check_glob_within_copy_roots(pattern, copy_roots)?;
        let mut v = Vec::new();
        for matched in
            glob::glob(pattern).with_context(|| format!("invalid glob pattern {:?}", spec.src))?
        {
            v.push(matched.with_context(|| format!("resolving glob pattern {:?}", spec.src))?);
        }
        v.sort(); // reproducible order
        if v.is_empty() {
            bail!("no files match {:?}", spec.src);
        }
        v
    } else {
        vec![spec.source().to_path_buf()]
    };

    let multiple = matches.len() > 1;
    if multiple && !spec.destination_is_directory() {
        // Docker: copying multiple sources requires dst to end with `/`
        // We're stricter than Docker (which would accept this if the dst
        // already exists as a dir on the host) — but we have no host fs to
        // consult, so we require the slash
        bail!(
            "multiple sources matched but dst {:?} is not a directory \
             (add a trailing slash)",
            spec.dst
        );
    }

    let mut opened_matches = Vec::with_capacity(matches.len());
    let mut any_is_dir = false;
    for src in matches {
        let source = open_copy_source(&src, copy_roots)?;
        let is_dir = matches!(source, OpenedSource::Dir(_));
        any_is_dir |= is_dir;
        opened_matches.push((src, source, is_dir));
    }

    let dst_is_dir = spec.destination_is_directory() || multiple || any_is_dir;

    let mut out = Vec::with_capacity(opened_matches.len());
    for (src, source, is_dir) in opened_matches {
        let dst = if is_dir {
            normalize_image_path(strip_trailing_slash(spec.destination()))
        } else if dst_is_dir {
            let basename = src
                .file_name()
                .ok_or_else(|| anyhow!("source has no filename: {}", src.display()))?
                .to_str()
                .with_context(|| {
                    format!("source filename is not valid UTF-8: {}", src.display())
                })?;
            normalize_image_path(&join_posix(
                strip_trailing_slash(spec.destination()),
                basename,
            ))
        } else {
            normalize_image_path(spec.destination())
        };
        out.push(ResolvedEntry { src, source, dst });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_basic() {
        let s = CopySpec::from_str("./app:/usr/bin/app").unwrap();
        assert_eq!(s.source(), Path::new("./app"));
        assert_eq!(s.destination(), "/usr/bin/app");
        assert!(!s.destination_is_directory());
        assert_eq!(s.mode(), None);
        assert_eq!(s.chown(), None);
    }

    #[test]
    fn parse_trailing_slash_marks_dst_as_dir() {
        let s = CopySpec::from_str("./app:/usr/bin/").unwrap();
        assert!(s.destination_is_directory());
        assert_eq!(s.destination(), "/usr/bin/");
    }

    #[test]
    fn parse_mode_via_options() {
        let s = CopySpec::from_str("./app:/usr/bin/app,mode=0755").unwrap();
        assert_eq!(s.mode(), Some(0o755));
    }

    #[test]
    fn parse_chmod_alias_works() {
        // Dockerfile users know `--chmod=`; accept it as alias for `mode`
        let s = CopySpec::from_str("./app:/x,chmod=0700").unwrap();
        assert_eq!(s.mode(), Some(0o700));
    }

    #[test]
    fn parse_chown_uid_gid() {
        let s = CopySpec::from_str("./app:/x,chown=1000:2000").unwrap();
        assert_eq!(
            s.chown(),
            Some(Owner {
                uid: 1000,
                gid: 2000
            })
        );
    }

    #[test]
    fn parse_chown_uid_only_defaults_gid_to_zero() {
        let s = CopySpec::from_str("./app:/x,chown=1000").unwrap();
        assert_eq!(s.chown(), Some(Owner { uid: 1000, gid: 0 }));
    }

    #[test]
    fn parse_combined_mode_and_chown() {
        let s = CopySpec::from_str("./app:/x,mode=0755,chown=1000:1000").unwrap();
        assert_eq!(s.mode(), Some(0o755));
        assert_eq!(
            s.chown(),
            Some(Owner {
                uid: 1000,
                gid: 1000
            })
        );
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(CopySpec::from_str("just-a-path").is_err());
        assert!(CopySpec::from_str(":/dst").is_err());
        assert!(CopySpec::from_str("./src:").is_err());
        assert!(CopySpec::from_str("./src:/dst,mode=99x").is_err()); // non-octal
        assert!(CopySpec::from_str("./src:/dst,mode=017777").is_err());
        assert!(CopySpec::from_str("./src:/dst,chown=alice").is_err()); // non-numeric
        assert!(CopySpec::from_str("./src:/dst,unknownopt=1").is_err());
        assert!(CopySpec::from_str("./src:/app/../escape").is_err());
        assert!(CopySpec::from_str("./src:/app//file").is_err());
    }

    #[test]
    fn windows_drive_and_single_character_sources_are_unambiguous() {
        for raw in [
            r"C:\work\app.exe:/app/app.exe,mode=0755,chown=10:20",
            "C:/work/app.exe:/app/app.exe,mode=0755,chown=10:20",
        ] {
            let spec: CopySpec = raw.parse().unwrap();
            assert!(spec.source().to_str().unwrap().starts_with("C:"));
            assert_eq!(spec.destination(), "/app/app.exe");
            assert_eq!(spec.chown(), Some(Owner { uid: 10, gid: 20 }));
        }
        let spec: CopySpec = "a:/app/a,chown=10:20".parse().unwrap();
        assert_eq!(spec.source(), Path::new("a"));
        assert_eq!(spec.destination(), "/app/a");
    }

    #[test]
    fn literal_artifacts_and_glob_base_directories_preserve_brackets() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("project[debug]");
        std::fs::create_dir(&base).unwrap();
        let artifact = base.join("app[1]");
        std::fs::write(&artifact, b"artifact").unwrap();
        let spec = CopySpec::executable(&artifact, "/app/main").unwrap();
        assert_eq!(resolve_targets(&spec).unwrap()[0].src, artifact);
        let mut glob: CopySpec = "app*:/app/".parse().unwrap();
        glob.resolve_relative_to(&base).unwrap();
        assert_eq!(resolve_targets(&glob).unwrap()[0].src, artifact);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_source_is_supported_with_explicit_destination_but_not_renamed_lossily() {
        use std::os::unix::ffi::OsStringExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join(std::ffi::OsString::from_vec(b"app\xff".to_vec()));
        std::fs::write(&path, b"artifact").unwrap();
        let spec = CopySpec::executable(&path, "/app/main").unwrap();
        assert_eq!(resolve_targets(&spec).unwrap()[0].src, path);
        let spec = CopySpec::executable(&path, "/app/").unwrap();
        assert!(
            resolve_targets(&spec)
                .unwrap_err()
                .to_string()
                .contains("UTF-8")
        );
    }
}
