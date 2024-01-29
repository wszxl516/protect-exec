use aya_bpf::helpers;

#[macro_export]
macro_rules! array_get_mut {
    ($name: ident, $index: expr) => {
        unsafe { $name.get_ptr_mut($index).ok_or(0)?.as_mut().ok_or(0)? }
    };
}
#[macro_export]
macro_rules! read_bytes {
    ($src: expr, $dest: expr) => {{
        pub use ::aya_bpf;
        unsafe {
            aya_bpf::helpers::bpf_probe_read_kernel_str_bytes($src, $dest).map_err(|_| 0)?
        }
    }};
}

#[macro_export]
macro_rules! read_struct_from_ctx {
    ($ctx: ident,$index: expr, $dest: ty) => {{
        pub use ::aya_bpf;
        unsafe {
            aya_bpf::helpers::bpf_probe_read_kernel($ctx.arg::<*const $dest>($index))
                .map_err(|e| e as i32)?
        }
    }};
}

pub fn read_struct<T: Sized>(dest: &mut T, src: *const u8) -> Result<(), i32> {
    unsafe {
        let exec_slice = core::slice::from_raw_parts_mut(
            dest as *const T as *mut u8,
            core::mem::size_of::<T>(),
        );
        helpers::bpf_probe_read_kernel_buf(src, exec_slice)
            .map_err(|_| 0)?;
    }
    Ok(())
}