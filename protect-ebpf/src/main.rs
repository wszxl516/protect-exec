#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(static_mut_refs)]
#![allow(unnecessary_transmutes)]
#![allow(improper_ctypes_definitions)]
#![feature(stmt_expr_attributes)]
#![allow(never_type_fallback_flowing_into_unsafe)]
use aya_ebpf::{macros::lsm, programs::LsmContext};
mod exec;
mod kill;
mod tools;
mod vmlinuz;
use aya_ebpf::maps::{PerCpuArray, PerfEventArray};
use protect_common::{Event};
use aya_ebpf::macros::map;

#[map]
pub static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);
#[map]
pub static EVENT_BUFFER: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);
#[lsm(hook = "bprm_creds_from_file")]
pub fn protect_execve(ctx: LsmContext) -> i32 {
    exec::try_bprm_check_security(ctx).unwrap_or_else(|ret| ret)
}
#[lsm(hook = "task_kill")]
pub fn protect_kill(ctx: LsmContext) -> i32 {
    kill::try_kill_check_security(ctx).unwrap_or_else(|ret|ret)
}
#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
