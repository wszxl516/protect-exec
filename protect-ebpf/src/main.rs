#![feature(panic_info_message)]
#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
mod macros;
mod vmlinuz;

use aya_bpf::macros::map;
use aya_bpf::maps::{BloomFilter, PerCpuArray, PerfEventArray};
use aya_bpf::{macros::lsm, memset, programs::LsmContext, BpfContext};
use aya_log_ebpf::debug;
use protect_common::{Event, MAX_BLACK_LIST, PATH};
use vmlinuz::linux_binprm;

#[map]
static mut EVENT: PerfEventArray<Event> = PerfEventArray::with_max_entries(0, 0);
#[map]
static mut BUFFER: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut BLACK_LIST: BloomFilter<PATH> = BloomFilter::with_max_entries(MAX_BLACK_LIST as u32, 0);

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    try_bprm_check_security(ctx).unwrap_or_else(|ret| ret)
}

fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm = read_struct_from_ctx!(ctx, linux_binprm);
    let event = array_get_mut!(BUFFER, 0);
    unsafe { memset(event as *mut Event as *mut u8, 0, Event::SIZE) };
    event.uid = ctx.uid();
    event.gid = ctx.gid();
    read_str!(bprm.filename as *const u8, event.path.as_mut_slice());

    let ret = match black_list_filter(event) {
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

fn black_list_filter(event: &mut Event) -> bool {
    unsafe {
        match BLACK_LIST.contains(&event.path) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
