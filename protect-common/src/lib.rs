#![no_std]
use core::{fmt::Display};
use num_enum::{IntoPrimitive, TryFromPrimitive};

pub const PATH_MAX: usize = 4096;
pub const MAX_BLACK_LIST: usize = 1024;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct GlobalInode{
    pub inode: u64,
    pub device: u64
}
impl Display for GlobalInode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.device, self.inode)
    }
}
impl GlobalInode {
    pub fn value(&self)-> u128{
        (self.device as u128).overflowing_shl(64).0 | (self.inode as u128)
    }
}
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum EventType {
    Exec{
        ppid: i32, 
        parent: [u8; 16]
    },
    Kill{
        sig_code: i32, 
        sig_no: i32
    }
}
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Event {
    pub inode: GlobalInode,
    pub path: [u8; PATH_MAX],
    pub uid: u32,
    pub gid: u32,
    pub event: EventType,
    pub denied: bool,
}

impl Event {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/*/usr/include/asm-generic/siginfo.h*/
#[repr(i32)]
#[derive(IntoPrimitive, TryFromPrimitive, Debug, derive_more::Display, Default)]
#[allow(non_camel_case_types)]
pub enum SignalSource {
    SI_USER = 0,      /* sent by kill, sigsend, raise */
    SI_KERNEL = 0x80, /* sent by the kernel from somewhere */
    SI_QUEUE = -1,    /* sent by sigqueue */
    SI_TIMER = -2,    /* sent by timer expiration */
    SI_MESGQ = -3,    /* sent by real time mesq state change */
    SI_ASYNCIO = -4,  /* sent by AIO completion */
    SI_SIGIO = -5,    /* sent by queued SIGIO */
    SI_TKILL = -6,    /* sent by tkill system call */
    SI_DETHREAD = -7, /* sent by execve() killing subsidiary threads */
    SI_ASYNCNL = -60, /* sent by glibc async name lookup completion */
    #[default]
    Unknown
}

#[repr(i32)]
#[derive(IntoPrimitive, TryFromPrimitive, Debug,  derive_more::Display, Default)]
#[allow(non_camel_case_types)]
pub enum SignalCode {
    SIG0 = 0,         // 0: Reserved signal, usually not used.
    SIGHUP = 1,       // 1: Hangup signal, often sent when the terminal is closed.
    SIGINT = 2,       // 2: Interrupt signal, commonly triggered by pressing Ctrl+C.
    SIGQUIT = 3,      // 3: Quit signal, generates a core dump when the process exits.
    SIGILL = 4,       // 4: Illegal instruction signal.
    SIGTRAP = 5,      // 5: Trap signal, used for debugging (e.g., breakpoints).
    SIGABRT = 6,      // 6: Abort signal, typically sent when a process calls abort().
    SIGBUS = 7,       // 7: Bus error signal, indicates invalid memory access or hardware failure.
    SIGFPE = 8,       // 8: Floating-point exception, such as division by zero.
    SIGKILL = 9,      // 9: Kill signal, used to terminate a process forcefully (cannot be caught).
    SIGUSR1 = 10,     // 10: User-defined signal 1.
    SIGSEGV = 11,     // 11: Segmentation fault, occurs when accessing invalid memory.
    SIGUSR2 = 12,     // 12: User-defined signal 2.
    SIGPIPE = 13,     // 13: Broken pipe signal, typically caused by writing to a pipe with no reader.
    SIGALRM = 14,     // 14: Alarm signal, triggered by a timer expiration.
    SIGTERM = 15,     // 15: Termination signal, gracefully asks a process to terminate.
    SIGSTKFLT = 16,   // 16: Stack fault signal, related to stack errors.
    SIGCHLD = 17,     // 17: Child process state change signal.
    SIGCONT = 18,     // 18: Continue signal, resumes a stopped process.
    SIGSTOP = 19,     // 19: Stop signal, stops a process.
    SIGTSTP = 20,     // 20: Stop signal sent from terminal (usually Ctrl+Z).
    SIGTTIN = 21,     // 21: Background process tries to read from the terminal.
    SIGTTOU = 22,     // 22: Background process tries to write to the terminal.
    SIGURG = 23,      // 23: Urgent condition on socket (e.g., out-of-band data).
    SIGXCPU = 24,     // 24: CPU time limit exceeded.
    SIGXFSZ = 25,     // 25: File size limit exceeded.
    SIGVTALRM = 26,   // 26: Virtual timer expired signal.
    SIGPROF = 27,     // 27: Profiling timer expired signal.
    SIGWINCH = 28,    // 28: Window size change signal.
    SIGIO = 29,       // 29: Asynchronous I/O signal.
    SIGPWR = 30,      // 30: Power failure signal.
    SIGSYS = 31,      // 31: Invalid system call signal.
    #[default]
    Unknown
}