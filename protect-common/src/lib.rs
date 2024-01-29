#![no_std]

pub const PATH_MAX: usize = 4096;
pub const MAX_BLACK_LIST: usize = 1024;

pub type PATH = [u8; PATH_MAX];

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub path: PATH,
    pub uid: u32,
    pub gid: u32,
    pub ppid: u32,
    pub parent: [u8; 16],
    pub denied: bool,
}

impl Event {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}
