use std::collections::HashSet;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process;

use aya::Bpf;
use aya::maps::{BloomFilter, MapData};
use clap::Parser;
use log::{debug, info};
use walkdir::{DirEntryExt, WalkDir};

use crate::version::KERNEL_VERSION_STR;

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

fn version_check(args :&Args){
    if args.kernel_version {
        println!("{}", KERNEL_VERSION_STR);
        process::exit(0)

    }
    let mut fd = std::fs::File::open("/proc/version").unwrap();
    let mut version = String::new();
    fd.read_to_string(&mut version).unwrap();
    let version = version.strip_suffix("\n").unwrap();
    if KERNEL_VERSION_STR !=  version{
        println!("program kernel version: {}", KERNEL_VERSION_STR);
        println!("current kernel version: {}", version);
        println!("Please recompile otherwise errors may occur");
        process::exit(0)

    }
}
fn black_list(args :&Args, bpf: &mut Bpf){
    let mut files = HashSet::new();
    let mut black_list: BloomFilter<&mut MapData, u64> =
        BloomFilter::try_from(bpf.map_mut("BLACK_LIST").expect("")).unwrap();

    match args.bin.is_empty() {
        true => {}
        false => {
            let ino = PathBuf::from(args.bin.clone()).metadata().unwrap().ino();
            files.insert(ino);
        }
    }
    match args.dir.is_empty() {
        true => {}
        false => {
            debug!("Black list");
            files.extend(WalkDir::new(args.dir.clone())
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
                .map(|e| e.ino())
                .collect::<HashSet<u64>>());
        }
    }
    let mut count = 0u32;
    debug!("found {} file(s)", files.len());
    for file in files {
        black_list.insert(file, 0).unwrap();
        count += 1;
    }
    info!("{} elf file(s) added to Black list", count);
}
pub fn setup(bpf: &mut Bpf) {
    let args = Args::parse();
    version_check(&args);
    black_list(&args, bpf)
}

pub fn check_permission(){
    if unsafe {libc::geteuid()} != 0{
        eprintln!("currently only supports running as the root user.");
        process::exit(1);
    }
}
