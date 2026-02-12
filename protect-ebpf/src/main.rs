#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(static_mut_refs)]
#![allow(unnecessary_transmutes)]
#![allow(improper_ctypes_definitions)]
use aya_ebpf::macros::map;
use aya_ebpf::maps::{BloomFilter, PerCpuArray, PerfEventArray};
use aya_ebpf::{helpers, macros::lsm, programs::LsmContext};
use aya_ebpf::{memset, EbpfContext};
use aya_log_ebpf::debug;

use crate::vmlinuz::{file, linux_binprm, task_struct};
use protect_common::{Event, GlobalInode, MAX_BLACK_LIST};

mod tools;
mod vmlinuz;
#[map]
static mut BLACK_LIST: BloomFilter<u128> = BloomFilter::with_max_entries(MAX_BLACK_LIST as u32, 0);
#[map]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);
#[map]
static EVENT_BUFFER: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[lsm(hook = "bprm_creds_from_file")]
pub fn protect_execve(ctx: LsmContext) -> i32 {
    try_bprm_check_security(ctx).unwrap_or_else(|ret| ret)
}

fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm_addr = unsafe { ctx.arg::<*const linux_binprm>(0) };
    let event = array_get_mut!(EVENT_BUFFER, 0);
    unsafe {
        memset(event as *mut Event as *mut u8, 0, Event::SIZE);
    }
    let current = unsafe { helpers::bpf_get_current_task_btf() as *const task_struct };
    event.uid = ctx.uid();
    event.gid = ctx.gid();
    event.ppid = read_struct_field!(current, tgid)?;
    let real_parent = read_struct_field!(current, real_parent)?;
    let parent_comm = read_struct_field!(real_parent, comm)?;
    read_bytes!(parent_comm.as_ptr().cast(), event.parent.as_mut_slice());
    let filename_ptr = read_struct_field!(bprm_addr, filename)?;
    read_bytes!(filename_ptr.cast(), event.path.as_mut_slice());
    event.inode = get_global_inode(&ctx)?;
    let denied = event.denied;
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
    EVENTS.output(&ctx, event, 0);
    debug!(
        &ctx,
        "finished bprm_check_security: {}",
        match denied {
            true => "Denied",
            false => "Allowed",
        }
    );
    ret
}

fn get_global_inode(ctx: &LsmContext) -> Result<GlobalInode, i32> {
    let file_addr = unsafe { ctx.arg::<*const file>(1) };
    let inode = read_struct_field!(file_addr, f_inode)?;
    let i_sb = read_struct_field!(inode, i_sb)?;
    let s_dev = read_struct_field!(i_sb, s_dev)?;
    let i_no = read_struct_field!(inode, i_ino)?;
    let minor = MINOR!(s_dev);
    let major = MAJOR!(s_dev);
    Ok(GlobalInode {
        device: makedev!(major, minor),
        inode: i_no,
    })
}

fn black_list_filter(ino: GlobalInode) -> bool {
    unsafe {
        match BLACK_LIST.contains(&ino.value()) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
