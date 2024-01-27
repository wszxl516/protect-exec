#[macro_export]
macro_rules! array_get_mut {
    ($name: ident, $index: expr) => {
        unsafe { $name.get_ptr_mut($index).ok_or(1)?.as_mut().ok_or(0)? }
    };
}
#[macro_export]
macro_rules! read_str {
    ($src: expr, $dest: expr) => {{
        pub use ::aya_bpf;
        unsafe {
            aya_bpf::helpers::bpf_probe_read_kernel_str_bytes($src, $dest).map_err(|e| e as i32)?
        }
    }};
}

#[macro_export]
macro_rules! read_struct_from_ctx {
    ($ctx: ident, $dest: ty) => {{
        pub use ::aya_bpf;
        unsafe {
            aya_bpf::helpers::bpf_probe_read_kernel($ctx.arg::<*const $dest>(0))
                .map_err(|e| e as i32)?
        }
    }};
}
