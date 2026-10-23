//! `ophan --upgrade`: installs a GitHub release over the installed binary.
//!
//! The release archive and its `.sha256` are downloaded with `curl`, the checksum is verified,
//! and the new binary must report the expected version and accept the current configuration
//! before it replaces the installed one. The previous binary is kept next to it as `ophan.old`.
//! The running instance then gets `SIGHUP` and hands its listeners over to the new binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use sha2::{Digest, Sha256};

/// Release requested by `--upgrade`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseTarget {
    Latest,
    Version(String),
}

impl FromStr for ReleaseTarget {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("latest") {
            return Ok(Self::Latest);
        }

        let version = s.strip_prefix('v').unwrap_or(s);
        let valid = version.starts_with(|c: char| c.is_ascii_digit())
            && version.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));

        if valid {
            Ok(Self::Version(version.to_string()))
        } else {
            Err("expected 'latest' or a version like 0.1.32")
        }
    }
}

pub struct Release {
    exe: PathBuf,
    target: ReleaseTarget,
}

impl Release {
    const REPO: &str = "zsweiter/ophan";
    const CURRENT: &str = env!("CARGO_PKG_VERSION");

    pub fn new(target: ReleaseTarget) -> Result<Self, String> {
        let exe = std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(|e| format!("cannot locate the ophan binary: {e}"))?;

        Ok(Self { exe, target })
    }

    pub fn exe(&self) -> &Path {
        &self.exe
    }

    /// Installs the requested release. Returns `None` when that version is already installed.
    pub fn install(&self, config: &Path) -> Result<Option<String>, String> {
        self.ensure_self_managed()?;

        let version = match &self.target {
            ReleaseTarget::Latest => Self::latest_version()?,
            ReleaseTarget::Version(version) => version.clone(),
        };

        if version == Self::CURRENT {
            return Ok(None);
        }

        match (&self.target, Self::is_newer(&version, Self::CURRENT)) {
            (ReleaseTarget::Latest, false) => {
                return Err(format!(
                    "the latest published release ({version}) is older than the installed {}; pass a version to install it anyway",
                    Self::CURRENT
                ));
            },
            (ReleaseTarget::Version(_), false) => println!("Installing {version}, older than the installed {}", Self::CURRENT),
            _ => {},
        }

        let package = Self::package_name(&version)?;
        let url = format!(
            "https://github.com/{}/releases/download/v{version}/{package}.tar.gz",
            Self::REPO
        );

        let work = WorkDir::create()?;
        let archive = work.path().join(format!("{package}.tar.gz"));
        let checksum = work.path().join(format!("{package}.tar.gz.sha256"));

        println!("Downloading {url}");
        Self::download(&url, &archive)?;
        Self::download(&format!("{url}.sha256"), &checksum)?;
        Self::verify_checksum(&archive, &checksum)?;

        Self::run(
            Command::new("tar").arg("-xzf").arg(&archive).arg("-C").arg(work.path()),
            "extract the release",
        )?;

        let binary = work.path().join(&package).join("ophan");
        Self::check_binary(&binary, &version, config)?;
        self.replace_with(&binary)?;

        Ok(Some(version))
    }

    /// Sends `SIGHUP` to the instance recorded in the PID file, which hands its listeners
    /// over to the installed binary. Returns its PID, or `None` when no instance runs.
    pub fn reload_running(pid_file: Option<&str>, config: &Path) -> Result<Option<i32>, String> {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        let pid_path = crate::sys::pid::effective_pid_path(pid_file, Some(&config.to_path_buf()));
        let Some(pid) = fs::read_to_string(&pid_path).ok().and_then(|s| s.trim().parse::<i32>().ok()) else {
            return Ok(None);
        };

        if kill(Pid::from_raw(pid), None).is_err() {
            return Ok(None);
        }

        kill(Pid::from_raw(pid), Signal::SIGHUP).map_err(|e| format!("cannot signal PID {pid}: {e}"))?;
        Ok(Some(pid))
    }

    /// Refuses installations that another tool owns.
    fn ensure_self_managed(&self) -> Result<(), String> {
        if Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() {
            return Err("running in a container: pull the new image instead".into());
        }

        let dpkg_owned = fs::read_to_string("/var/lib/dpkg/info/ophan.list")
            .is_ok_and(|files| files.lines().any(|line| Path::new(line) == self.exe));
        if dpkg_owned {
            return Err("installed with apt: install the new .deb with `apt install ./ophan_<version>_<arch>.deb`".into());
        }

        if self.exe.components().any(|c| c.as_os_str() == "Cellar") {
            return Err("installed with Homebrew: run `brew upgrade ophan`".into());
        }

        Ok(())
    }

    fn latest_version() -> Result<String, String> {
        let url = format!("https://api.github.com/repos/{}/releases/latest", Self::REPO);
        let output = Command::new("curl")
            .args(["-fsSL", "--proto", "=https", "--tlsv1.2", "-H", "Accept: application/vnd.github+json"])
            .arg(&url)
            .output()
            .map_err(|e| format!("cannot run curl: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "cannot query the latest release: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let body = String::from_utf8_lossy(&output.stdout);
        Self::tag_name(&body).ok_or_else(|| "the latest release has no tag".to_string())
    }

    /// Version in the `tag_name` field of a GitHub release response.
    fn tag_name(body: &str) -> Option<String> {
        let rest = &body[body.find("\"tag_name\"")? + "\"tag_name\"".len()..];
        let rest = rest.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
        let tag = &rest[..rest.find('"')?];

        Some(tag.strip_prefix('v').unwrap_or(tag).to_string())
    }

    /// Semantic version order: numeric `major.minor.patch`, and a pre-release before its release.
    fn is_newer(candidate: &str, current: &str) -> bool {
        fn parts(version: &str) -> (Vec<u64>, bool) {
            let (core, pre) = version.split_once('-').map_or((version, None), |(c, p)| (c, Some(p)));
            let numbers = core.split('.').map(|n| n.parse().unwrap_or(0)).collect();
            (numbers, pre.is_none())
        }

        parts(candidate) > parts(current)
    }

    /// `ophan-{version}-{os}-{arch}`, the release package built for this platform.
    fn package_name(version: &str) -> Result<String, String> {
        let os = match std::env::consts::OS {
            "linux" => "linux",
            "macos" => "macos",
            other => return Err(format!("no release is published for {other}")),
        };
        let arch = match std::env::consts::ARCH {
            "x86_64" => "x86_64",
            "aarch64" => "aarch64",
            other => return Err(format!("no release is published for {other}")),
        };

        Ok(format!("ophan-{version}-{os}-{arch}"))
    }

    fn download(url: &str, to: &Path) -> Result<(), String> {
        Self::run(
            Command::new("curl")
                .args(["-fsSL", "--proto", "=https", "--tlsv1.2", "--retry", "2", "-o"])
                .arg(to)
                .arg(url),
            "download the release",
        )
    }

    fn verify_checksum(archive: &Path, checksum: &Path) -> Result<(), String> {
        let expected = fs::read_to_string(checksum).map_err(|e| format!("cannot read the checksum: {e}"))?;
        let expected = expected.split_whitespace().next().unwrap_or_default().to_ascii_lowercase();

        let data = fs::read(archive).map_err(|e| format!("cannot read the archive: {e}"))?;
        let actual = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect::<String>();

        if expected != actual {
            return Err(format!("checksum mismatch: expected {expected}, got {actual}"));
        }

        Ok(())
    }

    /// The new binary must run and accept the current configuration. A binary that reports its
    /// version must report `version`; releases whose CLI lacks `--version` only get a warning.
    fn check_binary(binary: &Path, version: &str, config: &Path) -> Result<(), String> {
        let output = Command::new(binary)
            .arg("--version")
            .output()
            .map_err(|e| format!("the new binary does not run: {e}"))?;

        let reported = String::from_utf8_lossy(&output.stdout);
        match reported.split_whitespace().nth(1) {
            Some(found) if output.status.success() && found != version => {
                return Err(format!("the new binary reports ophan {found}, expected {version}"));
            },
            Some(_) if output.status.success() => {},
            _ => eprintln!("Warning: ophan {version} does not report its version; checking that it runs instead"),
        }

        if config.exists() {
            Self::run(
                Command::new(binary).arg("-t").arg("-c").arg(config),
                "validate the current configuration with the new binary",
            )
        } else {
            Self::run(Command::new(binary).arg("--help"), "run the new binary")
        }
    }

    /// Swaps the installed binary atomically and keeps the previous one as `<name>.old`.
    fn replace_with(&self, binary: &Path) -> Result<(), String> {
        let dir = self.exe.parent().ok_or("the binary has no parent directory")?;
        let name = self.exe.file_name().ok_or("the binary has no file name")?.to_string_lossy().into_owned();

        let staged = dir.join(format!(".{name}.new"));
        let backup = dir.join(format!("{name}.old"));
        let capabilities = Self::capabilities(&self.exe);

        let mode = fs::metadata(&self.exe)
            .map_err(|e| format!("cannot read {}: {e}", self.exe.display()))?
            .permissions();
        fs::copy(binary, &staged).map_err(|e| format!("cannot write {}: {e}", staged.display()))?;
        fs::set_permissions(&staged, mode).map_err(|e| format!("cannot set permissions on {}: {e}", staged.display()))?;

        let _ = fs::remove_file(&backup);
        fs::hard_link(&self.exe, &backup)
            .or_else(|_| fs::copy(&self.exe, &backup).map(|_| ()))
            .map_err(|e| format!("cannot keep the previous binary as {}: {e}", backup.display()))?;

        if let Err(e) = fs::rename(&staged, &self.exe) {
            let _ = fs::remove_file(&staged);
            return Err(format!("cannot replace {}: {e}", self.exe.display()));
        }

        if let Some(caps) = capabilities
            && let Err(e) = Self::run(Command::new("setcap").arg(&caps).arg(&self.exe), "restore file capabilities")
        {
            eprintln!("Warning: {e}; the previous binary had '{caps}'");
        }

        Ok(())
    }

    /// File capabilities of `path` as `setcap` takes them, e.g. `cap_net_bind_service=ep`.
    fn capabilities(path: &Path) -> Option<String> {
        let output = Command::new("getcap").arg(path).output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let caps = text.trim().strip_prefix(path.to_str()?)?.trim().trim_start_matches('=').trim();

        caps.starts_with("cap_").then(|| caps.to_string())
    }

    fn run(command: &mut Command, action: &str) -> Result<(), String> {
        let output = command.output().map_err(|e| format!("cannot {action}: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = if stderr.trim().is_empty() { stdout } else { stderr };
            Err(format!("cannot {action}: {}", detail.trim()))
        }
    }
}

/// Temporary download directory, removed on drop.
struct WorkDir(PathBuf);

impl WorkDir {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("ophan-upgrade-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;

        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_targets() {
        assert_eq!("latest".parse(), Ok(ReleaseTarget::Latest));
        assert_eq!("v0.1.32".parse(), Ok(ReleaseTarget::Version("0.1.32".into())));
        assert_eq!("0.2.0-rc.1".parse(), Ok(ReleaseTarget::Version("0.2.0-rc.1".into())));
        assert!("../../etc".parse::<ReleaseTarget>().is_err());
        assert!("1.0/x".parse::<ReleaseTarget>().is_err());
    }

    #[test]
    fn orders_versions() {
        assert!(Release::is_newer("0.1.32", "0.1.31"));
        assert!(Release::is_newer("0.2.0", "0.1.99"));
        assert!(!Release::is_newer("0.1.3", "0.1.31"));
        assert!(Release::is_newer("0.1.31", "0.1.31-rc.1"));
        assert!(!Release::is_newer("0.1.31-rc.1", "0.1.31"));
    }

    #[test]
    fn reads_tag_name() {
        let body = r#"{"url":"x","tag_name": "v0.1.32","name":"Release"}"#;
        assert_eq!(Release::tag_name(body).as_deref(), Some("0.1.32"));
        assert_eq!(Release::tag_name("{}"), None);
    }
}
