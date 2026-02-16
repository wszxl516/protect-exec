use super::tools::read_d_name;
use crate::vmlinuz::{kernel_siginfo, mm_struct, mm_struct__bindgen_ty_1, task_struct};
use crate::{array_get_mut, get_field_addr, read_struct_field};
use aya_ebpf::macros::map;
use aya_ebpf::maps::BloomFilter;
use aya_ebpf::{programs::LsmContext, EbpfContext};
use aya_log_ebpf::debug;
use num_enum::TryFromPrimitive;
use protect_common::{EventType, GlobalInode, SignalSource, MAX_BLACK_LIST};
#[map]
static mut KILL_BLACK_LIST: BloomFilter<GlobalInode> =
    BloomFilter::with_max_entries(MAX_BLACK_LIST as u32, 0);
pub fn try_kill_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let event = array_get_mut!(super::EVENT_BUFFER, 0);
    let task_addr = unsafe { ctx.arg::<*const task_struct>(0) };
    let siginfo_addr = unsafe { ctx.arg::<*const kernel_siginfo>(1) };
    let real = read_struct_field!(siginfo_addr, __bindgen_anon_1)?;
    event.uid = ctx.uid();
    event.gid = ctx.gid();
    event.inode = get_file_from_task(task_addr, &mut event.path).map_err(|_| 0)?;
    event.event = EventType::Kill {
        sig_code: 0,
        sig_no: 0,
    };
    if let EventType::Kill { sig_code, sig_no } = &mut event.event {
        *sig_code = real.si_code;
        *sig_no = real.si_signo;
    }
    event.denied = false;
    let ret = match SignalSource::try_from_primitive(real.si_code).map_err(|_| 0)? {
        SignalSource::SI_USER | SignalSource::SI_QUEUE | SignalSource::SI_TKILL => {
            match black_list_filter(event.inode) {
                true => {
                    event.denied = true;
                    Err(-1)
                }
                false => {
                    event.denied = false;
                    Ok(0)
                }
            }
        }
        _ => {
            debug!(&ctx, "other signal!{} ", real.si_signo);
            Ok(0)
        }
    };
    super::EVENTS.output(&ctx, event, 0);
    ret
}
fn get_file_from_task(task_addr: *const task_struct, buf: &mut [u8]) -> Result<GlobalInode, i32> {
    let mm = read_struct_field!(task_addr, mm)?;
    if mm.is_null() {
        return Err(-1);
    }
    let real_mm = get_field_addr!(mm, mm_struct, __bindgen_anon_1, mm_struct__bindgen_ty_1);
    let file_ptr = read_struct_field!(real_mm, exe_file)?;
    if file_ptr.is_null() {
        return Err(-1);
    }
    let f_path = read_struct_field!(file_ptr, __bindgen_anon_1.f_path)?;
    let path_dentry = f_path.dentry;
    let len = read_d_name(path_dentry, buf)?;
    buf[len] = 0;
    super::tools::get_global_inode(file_ptr)
}

fn black_list_filter(gino: GlobalInode) -> bool {
    unsafe {
        match KILL_BLACK_LIST.contains(&gino) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
