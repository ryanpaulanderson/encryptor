//! Atomic, no-clobber publication through a pinned Unix directory descriptor.

use crate::error::{Error, Result};
use rand_core::{OsRng, TryRngCore};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const TEMP_ATTEMPTS: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq)]
enum FaultPoint {
    Write,
    Flush,
    FileSync,
    Link,
    FirstDirectorySync,
    TemporaryUnlink,
    SecondDirectorySync,
}

#[cfg(test)]
std::thread_local! {
    static TEST_FAULT: std::cell::Cell<Option<FaultPoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn fault_is_active(point: FaultPoint) -> bool {
    TEST_FAULT.with(|fault| fault.get() == Some(point))
}

#[cfg(not(test))]
fn fault_is_active(_point: FaultPoint) -> bool {
    false
}

fn injected_failure(point: FaultPoint, message: &'static str) -> io::Result<()> {
    if fault_is_active(point) {
        Err(io::Error::other(message))
    } else {
        Ok(())
    }
}

/// Result of committing an output file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum PublicationOutcome {
    /// The requested name was durably published and the temporary name removed.
    Committed,
    /// The requested name was published, but removal of the temporary name failed.
    CommittedWithResidue,
}

fn split_output(path: &Path) -> Result<(PathBuf, OsString)> {
    let name = path
        .file_name()
        .ok_or(Error::InvalidFormat("output path has no filename"))?;
    if name == OsStr::new(".") || name == OsStr::new("..") || name.is_empty() {
        return Err(Error::InvalidFormat("invalid output filename"));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok((parent.to_path_buf(), name.to_os_string()))
}

fn open_directory(path: &Path) -> Result<rustix::fd::OwnedFd> {
    fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| Error::io("opening destination directory", source.into()))
}

fn random_temporary_name() -> Result<OsString> {
    let mut random = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| Error::EntropyFailure)?;
    let mut name = String::with_capacity(45);
    name.push_str(".encryptor-tmp-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").map_err(|_| Error::EntropyFailure)?;
    }
    Ok(OsString::from(name))
}

/// A same-directory temporary file that can be published without overwriting.
pub(crate) struct AtomicOutput {
    directory: rustix::fd::OwnedFd,
    final_name: OsString,
    temporary_name: Option<OsString>,
    file: File,
}

impl AtomicOutput {
    pub(crate) fn new(path: &Path, unix_mode: u32) -> Result<Self> {
        let (parent, final_name) = split_output(path)?;
        let directory = open_directory(&parent)?;
        let mode = match unix_mode {
            0o600 => Mode::RUSR | Mode::WUSR,
            0o644 => Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
            _ => return Err(Error::InvalidFormat("unsupported Unix output mode")),
        };

        for _ in 0..TEMP_ATTEMPTS {
            let temporary_name = random_temporary_name()?;
            match fs::openat(
                &directory,
                &temporary_name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                mode,
            ) {
                Ok(fd) => {
                    return Ok(Self {
                        directory,
                        final_name,
                        temporary_name: Some(temporary_name),
                        file: File::from(fd),
                    });
                }
                Err(source) if source == rustix::io::Errno::EXIST => continue,
                Err(source) => {
                    return Err(Error::io("creating temporary output", source.into()));
                }
            }
        }
        Err(Error::LimitExceeded(
            "could not allocate a unique temporary output name",
        ))
    }

    pub(crate) fn commit(mut self) -> Result<PublicationOutcome> {
        injected_failure(FaultPoint::Flush, "injected flush failure")
            .map_err(|source| Error::io("flushing temporary output", source))?;
        self.file
            .flush()
            .map_err(|source| Error::io("flushing temporary output", source))?;
        injected_failure(FaultPoint::FileSync, "injected file-sync failure")
            .map_err(|source| Error::io("synchronizing temporary output", source))?;
        self.file
            .sync_all()
            .map_err(|source| Error::io("synchronizing temporary output", source))?;

        let temporary_name = self
            .temporary_name
            .as_ref()
            .ok_or(Error::InvalidFormat("temporary output already consumed"))?;
        injected_failure(FaultPoint::Link, "injected publication failure")
            .map_err(|source| Error::io("publishing output without overwrite", source))?;
        fs::linkat(
            &self.directory,
            temporary_name,
            &self.directory,
            &self.final_name,
            AtFlags::empty(),
        )
        .map_err(|source| Error::io("publishing output without overwrite", source.into()))?;

        let first_sync = injected_failure(
            FaultPoint::FirstDirectorySync,
            "injected first directory-sync failure",
        )
        .and_then(|()| fs::fsync(&self.directory).map_err(Into::into));
        if let Err(source) = first_sync {
            let rollback = fs::unlinkat(&self.directory, &self.final_name, AtFlags::empty());
            let _ = fs::fsync(&self.directory);
            if rollback.is_err() {
                return Err(Error::PublishedButNotDurable);
            }
            return Err(Error::io(
                "synchronizing published output directory",
                source,
            ));
        }

        let cleanup_failed = injected_failure(
            FaultPoint::TemporaryUnlink,
            "injected temporary-unlink failure",
        )
        .and_then(|()| {
            fs::unlinkat(&self.directory, temporary_name, AtFlags::empty()).map_err(Into::into)
        })
        .is_err();
        // Publication has completed. If cleanup failed, preserve the sibling
        // name so the returned residue outcome accurately describes the
        // filesystem instead of silently retrying it from Drop.
        self.temporary_name = None;
        let second_sync = injected_failure(
            FaultPoint::SecondDirectorySync,
            "injected second directory-sync failure",
        )
        .and_then(|()| fs::fsync(&self.directory).map_err(Into::into));
        if second_sync.is_err() {
            return Err(Error::PublishedButNotDurable);
        }

        if cleanup_failed {
            Ok(PublicationOutcome::CommittedWithResidue)
        } else {
            Ok(PublicationOutcome::Committed)
        }
    }
}

impl Write for AtomicOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        injected_failure(FaultPoint::Write, "injected write failure")?;
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if let Some(temporary_name) = self.temporary_name.take() {
            let _ = fs::unlinkat(&self.directory, temporary_name, AtFlags::empty());
        }
    }
}

pub(crate) fn open_regular_nofollow(path: &Path) -> Result<File> {
    let (parent, name) = split_output(path)?;
    let directory = open_directory(&parent)?;
    let fd = fs::openat(
        &directory,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| Error::io("opening input without following symlinks", source.into()))?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|source| Error::io("reading input metadata", source))?;
    if !metadata.is_file() {
        return Err(Error::InvalidFormat("input is not a regular file"));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct FaultGuard;

    impl FaultGuard {
        fn set(point: FaultPoint) -> Self {
            TEST_FAULT.with(|fault| {
                assert!(fault.replace(Some(point)).is_none());
            });
            Self
        }
    }

    impl Drop for FaultGuard {
        fn drop(&mut self) {
            TEST_FAULT.with(|fault| fault.set(None));
        }
    }

    #[test]
    fn temporary_mode_is_set_at_creation_and_drop_cleans_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("result");
        let output = AtomicOutput::new(&destination, 0o600).expect("atomic output");
        let entries: Vec<_> = std::fs::read_dir(directory.path())
            .expect("temporary directory listing")
            .collect::<std::result::Result<_, _>>()
            .expect("directory entries");
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .file_name()
            .to_string_lossy()
            .starts_with(".encryptor-tmp-"));
        assert_eq!(
            entries[0]
                .metadata()
                .expect("temporary metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(output);
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("post-drop directory listing")
                .count(),
            0
        );
    }

    #[test]
    fn pinned_directory_and_concurrent_no_clobber_are_enforced() {
        let root = tempfile::tempdir().expect("temporary root");
        let destination_directory = root.path().join("destination");
        let moved_directory = root.path().join("pinned-destination");
        std::fs::create_dir(&destination_directory).expect("destination directory");
        let destination = destination_directory.join("result");
        let mut first = AtomicOutput::new(&destination, 0o600).expect("first writer");
        let mut second = AtomicOutput::new(&destination, 0o600).expect("second writer");
        first.write_all(b"first").expect("first contents");
        second.write_all(b"second").expect("second contents");

        std::fs::rename(&destination_directory, &moved_directory).expect("replace parent");
        std::fs::create_dir(&destination_directory).expect("replacement parent");
        assert_eq!(
            first.commit().expect("first commit"),
            PublicationOutcome::Committed
        );
        assert_eq!(
            std::fs::read(moved_directory.join("result")).expect("pinned result"),
            b"first"
        );
        assert!(!destination.exists());
        assert!(second.commit().is_err());
        assert_eq!(
            std::fs::read(moved_directory.join("result")).expect("unchanged result"),
            b"first"
        );
        assert!(std::fs::read_dir(&moved_directory)
            .expect("pinned directory")
            .filter_map(|entry| entry.ok())
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".encryptor-tmp-")));
    }

    #[test]
    fn every_atomic_publication_failure_stage_has_deliberate_state() {
        for point in [
            FaultPoint::Write,
            FaultPoint::Flush,
            FaultPoint::FileSync,
            FaultPoint::Link,
            FaultPoint::FirstDirectorySync,
        ] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let destination = directory.path().join("result");
            let guard = FaultGuard::set(point);
            let mut output = AtomicOutput::new(&destination, 0o600).expect("atomic output");
            let result = output.write_all(b"authenticated output");
            let result = result.and_then(|()| {
                output
                    .commit()
                    .map(|_| ())
                    .map_err(|error| io::Error::other(error.to_string()))
            });
            assert!(result.is_err(), "fault point unexpectedly succeeded");
            drop(guard);
            assert!(
                !destination.exists(),
                "prepublication fault left final path"
            );
            assert_eq!(
                std::fs::read_dir(directory.path())
                    .expect("post-fault directory")
                    .count(),
                0,
                "prepublication fault left temporary residue"
            );
        }

        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("result");
        let guard = FaultGuard::set(FaultPoint::TemporaryUnlink);
        let mut output = AtomicOutput::new(&destination, 0o600).expect("atomic output");
        output.write_all(b"committed output").expect("write");
        assert_eq!(
            output.commit().expect("committed-with-residue outcome"),
            PublicationOutcome::CommittedWithResidue
        );
        drop(guard);
        assert_eq!(
            std::fs::read(&destination).expect("published bytes"),
            b"committed output"
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("residue directory")
                .count(),
            2,
            "cleanup failure did not preserve the reported sibling residue"
        );

        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("result");
        let guard = FaultGuard::set(FaultPoint::SecondDirectorySync);
        let mut output = AtomicOutput::new(&destination, 0o600).expect("atomic output");
        output.write_all(b"committed output").expect("write");
        assert!(matches!(
            output.commit(),
            Err(Error::PublishedButNotDurable)
        ));
        drop(guard);
        assert_eq!(
            std::fs::read(&destination).expect("published bytes"),
            b"committed output"
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("postpublication directory")
                .count(),
            1,
            "successful unlink left an unexpected temporary name"
        );
    }
}
