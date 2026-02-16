use crate::vmlinuz::{file, linux_binprm, task_struct};
use crate::{array_get_mut, read_str, read_struct_field};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{BloomFilter};
use aya_ebpf::{helpers, programs::LsmContext, EbpfContext};
use aya_log_ebpf::debug;
use protect_common::{EventType, GlobalInode, MAX_BLACK_LIST};
use super::tools::get_global_inode;
#[map]
static mut EXEC_BLACK_LIST: BloomFilter<GlobalInode> =
    BloomFilter::with_max_entries(MAX_BLACK_LIST as u32, 0);

pub fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm_addr = unsafe { ctx.arg::<*const linux_binprm>(0) };
    let event = array_get_mut!(super::EVENT_BUFFER, 0);
    let current = unsafe { helpers::bpf_get_current_task_btf() as *const task_struct };
    event.uid = ctx.uid();
    event.gid = ctx.gid();
    event.event = EventType::Exec { ppid: 0, parent: [0;16] };
    if let EventType::Exec { ppid, ref mut parent } = &mut event.event {
        *ppid = read_struct_field!(current, tgid)?;
        let real_parent = read_struct_field!(current, real_parent)?;
        let parent_comm = read_struct_field!(real_parent, comm)?;
        read_str!(parent_comm.as_ptr().cast(), parent.as_mut_slice());
    }
    let filename_ptr = read_struct_field!(bprm_addr, filename)?;
    read_str!(filename_ptr.cast(), event.path.as_mut_slice());
    let file_addr = unsafe { ctx.arg::<*const file>(1) };
    event.inode = get_global_inode(file_addr)?;
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
    super::EVENTS.output(&ctx, event, 0);
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



fn black_list_filter(gino: GlobalInode) -> bool {
    unsafe {
        match EXEC_BLACK_LIST.contains(&gino) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
