use aya::maps::{BloomFilter, MapData};
use aya::Bpf;
use clap::Parser;
use log::debug;
use walkdir::WalkDir;

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
pub fn init_black_list(bpf: &mut Bpf) {
    let args = Args::parse();
    let mut black_list: BloomFilter<&mut MapData, PATH> =
        BloomFilter::try_from(bpf.map_mut("BLACK_LIST").expect("")).unwrap();

    match args.bin.is_empty() {
        true => {}
        false => {
            black_list.insert(PATH::from(Strings(args.bin)), 0).unwrap();
        }
    }
    match args.dir.is_empty() {
        true => {}
        false => {
            debug!("Black list");
            let files = WalkDir::new(args.dir)
                .follow_links(args.follow_links)
                .follow_root_links(true)
                .into_iter()
                .filter_map(|e| match e {
                    Ok(ee) => {
                        if ee.file_type().is_file() {
                            Some(ee)
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                })
                .map(|e| e.path().to_string_lossy().to_string())
                .collect::<Vec<String>>();
            let len = files.len();
            for file in files {
                debug!("add {} Black list", file);
                black_list.insert(PATH::from(Strings(file)), 0).unwrap();
            }
            debug!("Black list len: {}", len);
        }
    }
}
