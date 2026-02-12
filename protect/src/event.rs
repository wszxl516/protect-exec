use aya::maps::AsyncPerfEventArray;
use aya::util::online_cpus;
use aya::Ebpf;
use bytes::BytesMut;
use log::{debug, error};
use prettytable::{color, row, Attr, Cell, Row, Table};
use std::{ffi::CStr, io};
use users::{get_group_by_gid, get_user_by_uid};

use protect_common::Event;

pub fn wait_events(bpf: &mut Ebpf) -> Result<(), anyhow::Error> {
    let cpus = online_cpus().map_err(|err| anyhow::anyhow!("{:?}", err))?;
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").expect(""))?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        tokio::task::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(Event::SIZE); 10];
            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        debug!(
                            "fetch {} entrys, lost {} entrys on cpu {}!",
                            events.read, events.lost, cpu
                        );
                        buffers[0..events.read].iter().for_each(|buf| {
                            let event = unsafe { (buf.as_ptr() as *const Event).read() };
                            print_event(&event, cpu);
                        });
                    }
                    Err(err) => error!("failed to fetch event: {}", err),
                }
            }
        });
    }
    Ok(())
}

fn print_event(event: &Event, cpu: u32) {
    let mut table = Table::new();
    let pathname = CStr::from_bytes_until_nul(&event.path)
        .unwrap_or(c"Unknown")
        .to_str()
        .unwrap_or("Unknown");
    let user_name = match get_user_by_uid(event.uid) {
        None => format!("{}", event.uid),
        Some(name) => name.name().to_string_lossy().to_string(),
    };
    let group_name = match get_group_by_gid(event.gid) {
        None => format!("{}", event.gid),
        Some(name) => name.name().to_string_lossy().to_string(),
    };
    let parent = CStr::from_bytes_until_nul(&event.parent)
        .unwrap_or(c"Unknown")
        .to_str()
        .unwrap_or("Unknown");
    table.set_titles(row![
        "cpu",
        "action",
        "user",
        "group",
        "parent",
        "dev/inode",
        "program"
    ]);
    table.add_row(Row::new(vec![
        Cell::new(format!("{}", cpu).as_str()).with_style(Attr::ForegroundColor(color::BLUE)),
        match event.denied {
            true => Cell::new("Denied").with_style(Attr::ForegroundColor(color::RED)),
            false => Cell::new("Allowed").with_style(Attr::ForegroundColor(color::GREEN)),
        },
        Cell::new(user_name.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_YELLOW)),
        Cell::new(group_name.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_YELLOW)),
        Cell::new(&format!("{}/{}", event.ppid, parent))
            .with_style(Attr::ForegroundColor(color::BRIGHT_WHITE)),
        Cell::new(&format!("{}/{}", event.inode.device, event.inode.inode))
            .with_style(Attr::ForegroundColor(color::BRIGHT_WHITE)),
        Cell::new(pathname).with_style(Attr::ForegroundColor(color::BRIGHT_WHITE)),
    ]));
    {
        //prevent overprinting when using multithreading
        let _stdout = io::stdout().lock();
        table.print_tty(true).unwrap();
    }
}
