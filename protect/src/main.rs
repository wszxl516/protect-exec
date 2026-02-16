use aya::{Btf, programs::Lsm};
use aya::{Ebpf, include_bytes_aligned};
use aya_log::EbpfLogger;
use log::{debug, info, warn};
use tokio::signal;

use crate::setup::{check_permission, setup};
use crate::event::wait_events;

//lsm types
//include/linux/lsm_hook_defs.h
mod event;
mod setup;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    check_permission();
    env_logger::init();
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/protect-ebpf"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("protect_execve")
    .ok_or(anyhow::anyhow!("program not found!"))?.try_into()?;
    program.load("bprm_creds_from_file", &btf)?;
    program.attach()?;

    let program: &mut Lsm = bpf.program_mut("protect_kill")
    .ok_or(anyhow::anyhow!("program not found!"))?.try_into()?;
    program.load("task_kill", &btf)?;
    program.attach()?;
    info!("program started!");
    setup(&mut bpf);
    wait_events(&mut bpf)?;
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");
    Ok(())
}

