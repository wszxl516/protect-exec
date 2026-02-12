pub const ERROR_FAULT: i32 = -1;
#[macro_export]
macro_rules! array_get_mut {
    ($name: ident, $index: expr) => {
        unsafe { &mut *($name.get_ptr_mut($index).ok_or(-1)?)}
    };
}
#[macro_export]
macro_rules! read_bytes {
    ($src: expr, $dest: expr) => {{
        pub use ::aya_ebpf;
        unsafe { aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes($src, $dest).map_err(|_| $crate::tools::ERROR_FAULT)? }
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
    ($obj: ident, $field: ident) => {
        unsafe {aya_ebpf::helpers::bpf_probe_read_kernel(&(*$obj).$field)
            .map_err(|_e| $crate::tools::ERROR_FAULT)}
    };
}