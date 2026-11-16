//! Safe, TOCTOU-resistant filesystem primitives using directory file descriptors,
//! `O_NOFOLLOW`, `fstat`, and root containment checks.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};

#[cfg(unix)]
use rustix::fs::{Dir, FileType, Mode, OFlags, fcntl_getfl, fcntl_setfl, fstat, openat};
#[cfg(unix)]
use rustix::io::Errno;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

/// A validated directory root used to confine COPY inputs in CI mode.
#[derive(Debug, Clone)]
pub struct CopyRoot {
    abs_root: PathBuf,
    canonical_root: PathBuf,
    #[cfg(unix)]
    dir_fd: Arc<OwnedFd>,
    #[cfg(unix)]
    dev_ino: (u64, u64),
}

impl CopyRoot {
    pub fn open(path: &Path) -> Result<Self> {
        let canonical_root = path
            .canonicalize()
            .with_context(|| format!("canonicalizing copy root {}", path.display()))?;
        let abs_root = std::path::absolute(path)
            .with_context(|| format!("resolving copy root {}", path.display()))?;

        #[cfg(unix)]
        {
            let dir_fd = open_dir_nofollow_or_canonical(&canonical_root)?;
            let stat = fstat(&dir_fd)
                .with_context(|| format!("stat copy root {}", canonical_root.display()))?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
                bail!("copy root is not a directory: {}", path.display());
            }
            let dev_ino = (stat.st_dev as u64, stat.st_ino as u64);
            Ok(Self {
                abs_root,
                canonical_root,
                dir_fd: Arc::new(dir_fd),
                dev_ino,
            })
        }

        #[cfg(not(unix))]
        {
            if !canonical_root.is_dir() {
                bail!("copy root is not a directory: {}", path.display());
            }
            Ok(Self {
                abs_root,
                canonical_root,
            })
        }
    }

    #[cfg(not(unix))]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_root
    }

    /// Check whether `path` is lexically contained within this root.
    /// Useful before an artifact file has been created (e.g., pre-build validation).
    pub fn contains_lexical(&self, path: &Path) -> Result<bool> {
        Ok(self.relative_subpath(path)?.is_some())
    }

    fn relative_subpath(&self, path: &Path) -> Result<Option<PathBuf>> {
        let abs = std::path::absolute(path)
            .with_context(|| format!("resolving path {}", path.display()))?;
        let normalized = lexical_normalize(&abs);
        if let Ok(rel) = normalized.strip_prefix(&self.canonical_root) {
            return Ok(Some(rel.to_path_buf()));
        }
        if let Ok(rel) = normalized.strip_prefix(&self.abs_root) {
            // Only accept abs_root if abs_root itself resolves to the same directory inode.
            #[cfg(unix)]
            {
                if let Ok(meta) = std::fs::metadata(&self.abs_root) {
                    use std::os::unix::fs::MetadataExt;
                    if (meta.dev(), meta.ino()) == self.dev_ino {
                        return Ok(Some(rel.to_path_buf()));
                    }
                }
            }
            #[cfg(not(unix))]
            {
                return Ok(Some(rel.to_path_buf()));
            }
        }
        Ok(None)
    }
}

/// An already-opened and validated COPY source (either a regular file or a pinned directory).
#[derive(Debug)]
pub enum OpenedSource {
    File(File),
    Dir(OpenedDir),
}

#[derive(Debug)]
pub struct OpenedDir {
    #[cfg(unix)]
    fd: OwnedFd,
    #[cfg(not(unix))]
    path: PathBuf,
}

impl OpenedDir {
    pub fn open_path(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let fd = open_dir_nofollow_or_canonical(path)?;
            Ok(Self { fd })
        }
        #[cfg(not(unix))]
        {
            if !path.is_dir() {
                bail!("not a directory: {}", path.display());
            }
            Ok(Self {
                path: path.to_path_buf(),
            })
        }
    }

    #[allow(dead_code)]
    pub fn try_clone(&self) -> Result<Self> {
        #[cfg(unix)]
        {
            let fd = openat(
                &self.fd,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .context("duplicating directory descriptor")?;
            Ok(Self { fd })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                path: self.path.clone(),
            })
        }
    }

    pub fn child_names_sorted(&self) -> Result<Vec<OsString>> {
        #[cfg(unix)]
        {
            let dir = Dir::read_from(&self.fd).context("reading directory entries")?;
            let mut names = Vec::new();
            for entry in dir {
                let entry = entry.context("iterating directory entries")?;
                let bytes = entry.file_name().to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                names.push(OsString::from_vec(bytes.to_vec()));
            }
            names.sort();
            Ok(names)
        }
        #[cfg(not(unix))]
        {
            let mut names = Vec::new();
            for entry in std::fs::read_dir(&self.path)
                .with_context(|| format!("reading directory {}", self.path.display()))?
            {
                let entry = entry?;
                names.push(entry.file_name());
            }
            names.sort();
            Ok(names)
        }
    }

    pub fn open_child(&self, name: &OsStr) -> Result<OpenedSource> {
        #[cfg(unix)]
        {
            open_at_nofollow(&self.fd, name, Path::new(name))
        }
        #[cfg(not(unix))]
        {
            let child = self.path.join(name);
            let meta = std::fs::symlink_metadata(&child)
                .with_context(|| format!("stat {}", child.display()))?;
            if meta.file_type().is_symlink() {
                bail!("symlink entries are not supported yet: {}", child.display());
            }
            if meta.is_dir() {
                Ok(OpenedSource::Dir(OpenedDir { path: child }))
            } else if meta.is_file() {
                let file =
                    File::open(&child).with_context(|| format!("open {}", child.display()))?;
                Ok(OpenedSource::File(file))
            } else {
                bail!(
                    "special file entries are not supported: {}",
                    child.display()
                );
            }
        }
    }

    pub fn open_regular_file_at(&self, name: &OsStr) -> Result<File> {
        match self.open_child(name)? {
            OpenedSource::File(file) => Ok(file),
            OpenedSource::Dir(_) => bail!("expected regular file, found directory: {:?}", name),
        }
    }
}

/// Open a COPY source path safely. When `copy_roots` is non-empty, the path must
/// resolve strictly inside at least one root and is traversed component-by-component
/// from the root's pinned directory descriptor with `O_NOFOLLOW`.
pub fn open_copy_source(path: &Path, copy_roots: &[CopyRoot]) -> Result<OpenedSource> {
    if copy_roots.is_empty() {
        return open_standalone_source(path);
    }

    for root in copy_roots {
        if let Some(rel) = root.relative_subpath(path)? {
            return open_within_root(root, &rel, path);
        }
    }

    bail!(
        "COPY source {} is outside allowed --copy-root directories",
        path.display()
    );
}

/// Check whether a path (or non-glob prefix) is lexically within at least one `CopyRoot`.
pub fn check_within_copy_roots_lexical(path: &Path, copy_roots: &[CopyRoot]) -> Result<()> {
    if copy_roots.is_empty() {
        return Ok(());
    }
    for root in copy_roots {
        if root.contains_lexical(path)? {
            return Ok(());
        }
    }
    bail!(
        "path {} is outside allowed --copy-root directories",
        path.display()
    );
}

pub fn check_glob_within_copy_roots(pattern: &str, copy_roots: &[CopyRoot]) -> Result<()> {
    if copy_roots.is_empty() {
        return Ok(());
    }
    let path = Path::new(pattern);
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            bail!("COPY glob pattern must not contain '..' when --copy-root is set: {pattern:?}");
        }
    }
    // Extract the longest literal directory prefix before the first glob metacharacter.
    // Unescape single-char bracket escapes (`[*]`, `[?]`, `[[]`, `[]]`) produced by `glob::Pattern::escape`.
    let mut prefix = PathBuf::new();
    for comp in path.components() {
        let s = comp.as_os_str().to_string_lossy();
        let unescaped = unescape_glob_literal(&s);
        if let Some(lit) = unescaped {
            prefix.push(lit);
        } else {
            break;
        }
    }
    if prefix.as_os_str().is_empty() {
        if path.is_relative() {
            prefix.push(".");
        } else {
            bail!("COPY glob pattern must be anchored inside --copy-root: {pattern:?}");
        }
    }
    check_within_copy_roots_lexical(&prefix, copy_roots)
}

fn unescape_glob_literal(component: &str) -> Option<String> {
    let mut out = String::with_capacity(component.len());
    let mut chars = component.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' | '?' => return None,
            '[' => {
                let inner = chars.next()?;
                let Some(']') = chars.next() else {
                    return None;
                };
                if matches!(inner, '*' | '?' | '[' | ']') {
                    out.push(inner);
                } else {
                    return None;
                }
            }
            other => out.push(other),
        }
    }
    Some(out)
}

fn open_within_root(root: &CopyRoot, rel: &Path, display_path: &Path) -> Result<OpenedSource> {
    #[cfg(unix)]
    {
        let mut components: Vec<&OsStr> = Vec::new();
        for comp in rel.components() {
            match comp {
                Component::Normal(part) => components.push(part),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    bail!(
                        "COPY source {} contains disallowed path component",
                        display_path.display()
                    );
                }
            }
        }
        if components.is_empty() {
            let dup = openat(
                root.dir_fd.as_fd(),
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("opening {}", display_path.display()))?;
            return Ok(OpenedSource::Dir(OpenedDir { fd: dup }));
        }

        let mut current: Option<OwnedFd> = None;
        for (idx, part) in components.iter().enumerate() {
            let parent_fd = current
                .as_ref()
                .map(AsFd::as_fd)
                .unwrap_or_else(|| root.dir_fd.as_fd());
            let is_last = idx + 1 == components.len();
            if is_last {
                return open_at_nofollow(parent_fd, *part, display_path);
            }
            let next_dir = openat(
                parent_fd,
                *part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|err| map_open_error(err, display_path))?;
            current = Some(next_dir);
        }
        unreachable!("non-empty components returned on last iteration")
    }

    #[cfg(not(unix))]
    {
        let target = root.canonical_path().join(rel);
        let canonical = target
            .canonicalize()
            .with_context(|| format!("resolving {}", display_path.display()))?;
        if !canonical.starts_with(root.canonical_path()) {
            bail!(
                "COPY source {} escapes allowed --copy-root via symlink",
                display_path.display()
            );
        }
        open_standalone_source(&target)
    }
}

fn open_standalone_source(path: &Path) -> Result<OpenedSource> {
    #[cfg(unix)]
    {
        open_at_nofollow(rustix::fs::CWD, path, path)
    }
    #[cfg(not(unix))]
    {
        let meta =
            std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if meta.file_type().is_symlink() {
            bail!("symlink sources are not supported yet: {}", path.display());
        }
        if meta.is_dir() {
            Ok(OpenedSource::Dir(OpenedDir {
                path: path.to_path_buf(),
            }))
        } else if meta.is_file() {
            let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
            Ok(OpenedSource::File(file))
        } else {
            bail!("special file sources are not supported: {}", path.display());
        }
    }
}

/// Open a regular file without following a trailing symlink (or special file).
pub fn open_regular_file_nofollow(path: &Path) -> Result<File> {
    match open_standalone_source(path)? {
        OpenedSource::File(file) => Ok(file),
        OpenedSource::Dir(_) => bail!("expected regular file, found directory: {}", path.display()),
    }
}

#[cfg(unix)]
pub fn file_dev_ino(file: &File) -> Result<(u64, u64)> {
    let stat = fstat(file).context("stat open file descriptor")?;
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

/// Reopen an independent read-only handle to the exact verified file inode.
pub fn reopen_verified_readonly(
    file: &File,
    fallback_path: &Path,
    #[cfg(unix)] expected_dev_ino: (u64, u64),
) -> Result<File> {
    #[cfg(target_os = "linux")]
    {
        let proc_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        match File::open(&proc_path) {
            Ok(reopened) => {
                let stat = fstat(&reopened).context("stat reopened descriptor")?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                    bail!("cached blob descriptor is not a regular file");
                }
                if (stat.st_dev as u64, stat.st_ino as u64) != expected_dev_ino {
                    bail!("cached blob inode mismatch on reopen");
                }
                return Ok(reopened);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // Fall back only if /proc/self/fd is unavailable (e.g. minimal chroot without procfs).
            }
            Err(err) => {
                return Err(err).context("reopening verified file descriptor");
            }
        }
    }

    let reopened = open_regular_file_nofollow(fallback_path)
        .with_context(|| format!("reopening verified file {}", fallback_path.display()))?;
    #[cfg(unix)]
    {
        let actual = file_dev_ino(&reopened)?;
        if actual != expected_dev_ino {
            bail!(
                "cached blob changed after verification ({})",
                fallback_path.display()
            );
        }
    }
    let _ = file;
    Ok(reopened)
}

#[cfg(unix)]
fn open_dir_nofollow_or_canonical(path: &Path) -> Result<OwnedFd> {
    openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening directory {}", path.display()))
}

#[cfg(unix)]
fn open_at_nofollow<Fd: AsFd, P: rustix::path::Arg>(
    dir_fd: Fd,
    path: P,
    display_path: &Path,
) -> Result<OpenedSource> {
    let fd = openat(
        dir_fd,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| map_open_error(err, display_path))?;

    let stat = fstat(&fd).with_context(|| format!("stat {}", display_path.display()))?;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile => {
            let flags = fcntl_getfl(&fd)
                .with_context(|| format!("getting file flags {}", display_path.display()))?;
            if flags.contains(OFlags::NONBLOCK) {
                fcntl_setfl(&fd, flags & !OFlags::NONBLOCK)
                    .with_context(|| format!("clearing O_NONBLOCK {}", display_path.display()))?;
            }
            Ok(OpenedSource::File(File::from(fd)))
        }
        FileType::Directory => Ok(OpenedSource::Dir(OpenedDir { fd })),
        FileType::Symlink => bail!(
            "symlink sources are not supported yet: {}",
            display_path.display()
        ),
        _ => bail!(
            "special file sources are not supported: {}",
            display_path.display()
        ),
    }
}

#[cfg(unix)]
fn map_open_error(err: Errno, display_path: &Path) -> anyhow::Error {
    if err == Errno::LOOP {
        anyhow!(
            "symlink sources are not supported yet: {}",
            display_path.display()
        )
    } else if err == Errno::NOENT {
        anyhow!("source does not exist: {}", display_path.display())
    } else {
        anyhow!("opening {}: {}", display_path.display(), err)
    }
}

/// Lexically normalize `.` and `..` components without resolving symlinks on disk.
pub fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !matches!(
                    out.components().next_back(),
                    None | Some(Component::RootDir | Component::Prefix(_))
                ) {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}
