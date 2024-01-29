use std::collections::HashSet;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use aya::Bpf;
use aya::maps::{BloomFilter, MapData};
use clap::Parser;
use log::{debug, info};
use walkdir::{DirEntryExt, WalkDir};

use protect_common::PATH;

pub struct Strings(pub String);

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
}

impl From<Strings> for PATH {
    fn from(s: Strings) -> Self {
        let mut buffer = [0u8; 4096];
        let buf = s.0.as_bytes();
        buffer[..buf.len()].as_mut().copy_from_slice(buf);
        buffer
    }
}

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

pub fn init_black_list(bpf: &mut Bpf) {
    let args = Args::parse();
    let mut files = HashSet::new();
    let mut black_list: BloomFilter<&mut MapData, u64> =
        BloomFilter::try_from(bpf.map_mut("BLACK_LIST").expect("")).unwrap();

    match args.bin.is_empty() {
        true => {}
        false => {
            let ino = PathBuf::from(args.bin).metadata().unwrap().ino();
            files.insert(ino);
        }
    }
    match args.dir.is_empty() {
        true => {}
        false => {
            debug!("Black list");
            files.extend(WalkDir::new(args.dir)
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
