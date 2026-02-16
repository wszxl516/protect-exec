use std::collections::HashSet;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process;

use aya::maps::{BloomFilter, MapData};
use aya::Ebpf;
use clap::Parser;
use log::{debug, info};
use walkdir::{DirEntryExt, WalkDir};
use protect_common::GlobalInode;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// elf file to add to black list
    #[arg(short, long, default_value = "")]
    bin: String,
    /// all elf file in dir to add to black list
    #[arg(short, long, default_value = "")]
    dir: String,
    /// if walk dir follow links
    #[arg(short, long, default_value_t = false)]
    follow_links: bool,
    /// linux kernel version that program compile for
    #[arg(short, long, default_value_t = false)]
    kernel_version: bool,
}

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

fn black_list(args: &Args, bpf: &mut Ebpf) {
    let mut files = HashSet::new();
    match args.bin.is_empty() {
        true => {}
        false => {
            let stat = PathBuf::from(args.bin.clone()).metadata().unwrap();
            files.insert((stat.dev(), stat.ino()));
        }
    }
    match args.dir.is_empty() {
        true => {}
        false => {
            debug!("Black list");
            files.extend(
                WalkDir::new(args.dir.clone())
                    .follow_links(args.follow_links)
                    .follow_root_links(true)
                    .into_iter()
                    .filter_map(|e| match e {
                        Ok(ee) => {
                            if ee.file_type().is_file() {
                                let mut f = std::fs::File::open(ee.path()).unwrap();
                                let mut magic = [0u8; 4];
                                f.read(&mut magic).unwrap();
                                match magic == ELF_MAGIC {
                                    true => Some(ee),
                                    false => None,
                                }
                            } else {
                                None
                            }
                        }
                        Err(_) => None,
                    })
                    .map(|e| {
                        let dev_id = match e.metadata() {
                            Ok(stat) => stat.dev(),
                            Err(_) => 0,
                        };
                        (dev_id, e.ino())
                    })
                    .collect::<HashSet<(u64, u64)>>(),
            );
        }
    }
    let count = files.len();
    debug!("found {} file(s)", count);
    let mut exec_black_list: BloomFilter<&mut MapData, u128> =
        BloomFilter::try_from(bpf.map_mut("EXEC_BLACK_LIST").expect("")).unwrap();
    for (dev, ino) in &files {
        exec_black_list.insert(GlobalInode{device: *dev, inode: *ino}.value(), 0).unwrap();
    }
    let mut kill_black_list: BloomFilter<&mut MapData, u128> =
        BloomFilter::try_from(bpf.map_mut("KILL_BLACK_LIST").expect("")).unwrap();
    for (dev, ino) in files {
        kill_black_list.insert(GlobalInode{device: dev, inode: ino}.value(), 0).unwrap();
    }
    info!("{} elf file(s) added to Black list", count);
}
pub fn setup(bpf: &mut Ebpf) {
    let args = Args::parse();
    black_list(&args, bpf)
}

pub fn check_permission() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("currently only supports running as the root user.");
        process::exit(1);
    }
}
