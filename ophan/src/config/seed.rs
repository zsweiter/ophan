use std::fs;
use std::io;
use std::path::Path;

/// Default configuration copied into an empty config directory, as container images ship it.
pub struct ConfigSeed;

impl ConfigSeed {
    /// Directory holding the default configuration.
    pub const ENV: &str = "OPHAN_CONFIG_SEED_DIR";

    /// Copies the seed directory next to `config` when `config` does not exist.
    /// Returns whether it seeded anything.
    pub fn apply(config: &Path) -> io::Result<bool> {
        let Some(seed) = std::env::var_os(Self::ENV) else {
            return Ok(false);
        };
        let seed = Path::new(&seed);

        if config.exists() || !seed.is_dir() {
            return Ok(false);
        }

        let target = config.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        Self::copy_dir(seed, target)?;

        Ok(true)
    }

    /// Copies `from` into `to`, keeping files that already exist.
    fn copy_dir(from: &Path, to: &Path) -> io::Result<()> {
        fs::create_dir_all(to)?;

        for entry in fs::read_dir(from)? {
            let entry = entry?;
            let target = to.join(entry.file_name());

            if entry.file_type()?.is_dir() {
                Self::copy_dir(&entry.path(), &target)?;
            } else if !target.exists() {
                fs::copy(entry.path(), &target)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_tree_without_overwriting() {
        let seed = tempfile::tempdir().unwrap();
        fs::create_dir_all(seed.path().join("gateways")).unwrap();
        fs::write(seed.path().join("master.conf"), "seed").unwrap();
        fs::write(seed.path().join("gateways/a.conf"), "a").unwrap();

        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join("gateways")).unwrap();
        fs::write(target.path().join("gateways/a.conf"), "mine").unwrap();

        ConfigSeed::copy_dir(seed.path(), target.path()).unwrap();

        assert_eq!(fs::read_to_string(target.path().join("master.conf")).unwrap(), "seed");
        assert_eq!(fs::read_to_string(target.path().join("gateways/a.conf")).unwrap(), "mine");
    }
}
