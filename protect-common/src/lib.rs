#![no_std]

pub const PATH_MAX: usize = 4096;
pub const MAX_BLACK_LIST: usize = 1024;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct GlobalInode{
    pub inode: u64,
    pub device: u64
}
impl GlobalInode {
    pub fn value(&self)-> u128{
        (self.device as u128).overflowing_shl(64).0 | (self.inode as u128)
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Event {
    pub inode: GlobalInode,
    pub path: [u8; PATH_MAX],
    pub uid: u32,
    pub gid: u32,
    pub ppid: i32,
    pub parent: [u8; 16],
    pub denied: bool,
}
impl Default for Event {
    fn default() -> Self {
        Self { path: [0; PATH_MAX], inode: Default::default(), uid: 0, gid: 0, ppid: 0, parent: [0;16], denied: Default::default() }
    }
}
impl Event {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}
