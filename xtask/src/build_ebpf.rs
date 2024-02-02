use std::{path::PathBuf, process::Command};
use std::io::{Seek, SeekFrom, Write};

use clap::Parser;

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
    /// Build the release target
    #[clap(long)]
    pub release: bool,
}

#[path = "../../protect/src/version.rs"]
mod kernel_version;
pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("protect-ebpf");
    let version = include_str!("/proc/version").strip_suffix("\n").unwrap();
    if version != kernel_version::KERNEL_VERSION_STR
    {
        println!("regenerate vmlinuz.rs");
        let gen_file = dir.join("src/vmlinuz.rs").to_string_lossy().to_string();
        let version_file = "protect/src/version.rs";
        let kernel_version_buf = format!("pub const KERNEL_VERSION_STR: &str = \"{}\";", version);
        let mut fd = std::fs::File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(version_file)?;
        fd.seek(SeekFrom::Start(0))?;
        fd.write_all(kernel_version_buf.as_bytes())?;
        fd.flush()?;
        let status = Command::new("aya-tool")
            .args(["generate",
                "linux_binprm",
                "task_struct",
                "--", "-o",
                &gen_file,
            ])
            .status()
            .expect("failed generate kernel api src/vmlinuz.rs");
        assert!(status.success());
    }
    let target = format!("--target={}", opts.target);
    let mut args = vec![
        "build",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];
    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}
