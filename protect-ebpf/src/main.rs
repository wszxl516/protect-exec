#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(static_mut_refs)]

use aya_bpf::{BpfContext, helpers, macros::lsm, memset, programs::LsmContext};
use aya_bpf::macros::map;
use aya_bpf::maps::{BloomFilter, PerCpuArray, PerfEventArray};
use aya_log_ebpf::{debug};

use protect_common::{Event, GlobalInode, MAX_BLACK_LIST};

use crate::tools::read_struct;
use crate::vmlinuz::{file, inode, linux_binprm, super_block, task_struct};

mod tools;
mod vmlinuz;

#[map]
static mut EVENT: PerfEventArray<Event> = PerfEventArray::with_max_entries(0, 0);
#[map]
static mut BUFFER: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut BLACK_LIST: BloomFilter<u128> = BloomFilter::with_max_entries(MAX_BLACK_LIST as u32, 0);

#[map]
static mut FILE: PerCpuArray<file> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut INODE: PerCpuArray<inode> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut SB: PerCpuArray<super_block> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut TASK: PerCpuArray<task_struct> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut BINPRM: PerCpuArray<linux_binprm> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "bprm_creds_from_file")]
pub fn protect_execve(ctx: LsmContext) -> i32 {
    try_bprm_check_security(ctx).unwrap_or_else(|ret| ret)
}

fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm = array_get_mut!(BINPRM, 0);
    let bprm_addr = unsafe { ctx.arg::<*const u8>(0) };
    read_struct(bprm, bprm_addr)?;
    let event = array_get_mut!(BUFFER, 0);
    unsafe { memset(event as *mut Event as *mut u8, 0, Event::SIZE) };
    let task = array_get_mut!(TASK, 0);
    unsafe { read_struct(task, helpers::bpf_get_current_task_btf() as *const u8)? }
    let parent_ptr = task.real_parent;
    read_struct(task, parent_ptr as *const u8)?;
    event.uid = ctx.uid();
    event.gid = ctx.gid();
    event.ppid = task.tgid as u32;
    read_bytes!(task.comm.as_ptr() as *const u8, event.parent.as_mut_slice());
    read_bytes!(bprm.filename as *const u8, event.path.as_mut_slice());
    event.inode = get_global_inode(&ctx)?;
    let ret = match black_list_filter(event.inode) {
        true => {
            event.denied = true;
            Err(-1)
        }
        false => {
            event.denied = false;
            Ok(0)
        }
    };
    unsafe { EVENT.output(&ctx, event, 0) };
    debug!(
        &ctx,
        "finished bprm_check_security: {}",
        match event.denied {
            true => "Denied",
            false => "Allowed",
        }
    );
    ret
}




fn get_global_inode(ctx: &LsmContext) -> Result<GlobalInode, i32> {
    let inode = array_get_mut!(INODE, 0);
    let exec_file = array_get_mut!(FILE, 0);
    let sb = array_get_mut!(SB, 0);
    let file_addr = unsafe { ctx.arg::<*const u8>(1) };
    read_struct(exec_file, file_addr)?;
    read_struct(inode, exec_file.f_inode as *const u8)?;
    read_struct(sb, inode.i_sb as *const u8)?;
    let minor = MINOR!(sb.s_dev);
    let major = MAJOR!(sb.s_dev);
    Ok(GlobalInode{device: makedev!(major,minor), inode:  inode.i_ino})
}


fn black_list_filter(ino: GlobalInode) -> bool {
    unsafe {
        match BLACK_LIST.contains(&ino.value()) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
