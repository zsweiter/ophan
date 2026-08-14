use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("CARGO_FEATURE_XDP").is_err() {
        return Ok(());
    }

    #[cfg(feature = "xdp")]
    {
        use std::path::PathBuf;
        use std::process::Command;
        
        let out_dir = PathBuf::from(env::var("OUT_DIR")?);
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
        let ophan_bpf_dir = manifest_dir.join("..").join("ophan-bpf");

        println!("cargo:rerun-if-changed={}", ophan_bpf_dir.display());

        let output = out_dir.join("ophan-bpf.o");

        let mut cmd = Command::new("cargo");
        cmd.args([
            "build",
            "--package",
            "ophan-bpf",
            "--features",
            "xdp",
            "-Z",
            "build-std=core",
            "--bins",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "--target-dir",
            out_dir.to_str().unwrap(),
            // Override the workspace profile to avoid bpf-linker incompatibilities
            "--config",
            "profile.release.lto=false",
            "--config",
            "profile.release.codegen-units=1",
        ])
        .env("RUSTUP_TOOLCHAIN", "nightly")
        .current_dir(&manifest_dir);

        // Clear RUSTFLAGS to avoid workspace-level flags that bpf-linker can't handle
        cmd.env_remove("RUSTC");
        cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");
        cmd.env_remove("RUSTFLAGS");
        cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");

        let status = cmd.status()?;

        if !status.success() {
            return Err("Failed to build ophan-bpf for BPF target".into());
        }

        let bpf_bin = out_dir.join("bpfel-unknown-none").join("release").join("ophan-bpf");

        std::fs::copy(&bpf_bin, &output)?;
    }

    Ok(())
}
