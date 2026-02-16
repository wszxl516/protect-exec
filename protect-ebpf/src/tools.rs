use crate::vmlinuz::{file, dentry};
use protect_common::{GlobalInode};
pub const ERROR_FAULT: i32 = -1;
#[macro_export]
macro_rules! array_get_mut {
    ($name: expr, $index: expr) => {
        unsafe { &mut *($name.get_ptr_mut($index).ok_or(-1)?)}
    };
}
#[macro_export]
macro_rules! read_str {
    ($src: expr, $dest: expr) => {{
        unsafe { aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes($src, $dest).map_err(|_| $crate::tools::ERROR_FAULT)? }
    }};
}
#[macro_export]
macro_rules! read_bytes {
    ($src: expr, $dest: expr) => {{
        unsafe { aya_ebpf::helpers::bpf_probe_read_kernel_buf($src, $dest).map_err(|_| $crate::tools::ERROR_FAULT)? }
    }};
}

//sys/sysmacros.h
#[macro_export]
macro_rules! MINOR {
    ($dev: expr) => {
        ((($dev) & ((1 << 20) - 1)) as u32)
    };
}
#[macro_export]
macro_rules! MAJOR {
    ($dev: expr) => {
        ((($dev) >> 20) as u32)
    };
}
#[macro_export]
macro_rules! makedev {
    ($major: expr, $minor: expr) => {
        ((((($major) & 0xfffff000).overflowing_shl(32).0)
            | ((($major) & 0x00000fff) << 8)
            | ((($minor) & 0xffffff00) << 12)
            | (($minor) & 0x000000ff)) as u64)
    };
}
#[macro_export]
macro_rules! read_struct_field {
    ($obj: ident, $field: ident $(.$subfield:ident)*) => {
        unsafe {aya_ebpf::helpers::bpf_probe_read_kernel(&(*$obj).$field $(.$subfield)*)
            .map_err(|_e| $crate::tools::ERROR_FAULT)}
    };
}
#[macro_export]
macro_rules! get_field_addr {
    ($obj: ident, $obj_ty: ty, $field: ident, $field_ty: ty) => {
     unsafe {
        $obj.add(core::mem::offset_of!($obj_ty, $field))
            .cast::<$field_ty>()
    }   
    };
}

pub fn get_global_inode(file_addr: *const file) -> Result<GlobalInode, i32> {
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
pub fn read_d_name(d: *const dentry, buf: &mut [u8]) -> Result<usize, i32> {
    let mut dentry_ptr = d;
    let mut stack: [*const dentry; 16] = [core::ptr::null(); 16];
    let mut idx = 0;
    while !d.is_null() && idx < stack.len() {
        stack[idx] = dentry_ptr;
        idx += 1;

        let parent = read_struct_field!(dentry_ptr, d_parent)? as *const dentry;
        if parent.is_null() || parent == dentry_ptr {
            break;
        }
        dentry_ptr = parent;
    }
    let mut used = 0;
    for index in (0..idx).rev() {
        let d_ptr = stack[index];
        let qstr = read_struct_field!(d_ptr, __bindgen_anon_1.d_name)?;
        let mut len = unsafe { qstr.__bindgen_anon_1.__bindgen_anon_1.len as usize};
        const MAX_NAME: usize = 64;
        if len > MAX_NAME {
            len = MAX_NAME;
        }
        if len > buf.len() {
            len = buf.len();
        }
        if used > buf.len() {
            break;
        }
        if used != 0 {
            buf[used - 1] = b'/'; 
        }
        read_bytes!(qstr.name, &mut buf[used..used + len]);
        if used != 0 {
            used += 1
        }
        used += len;

    }

    Ok(used)
}