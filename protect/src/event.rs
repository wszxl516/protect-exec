use aya::maps::AsyncPerfEventArray;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use prettytable::{Attr, Cell, color, Row, row, Table};
use protect_common::Event;
use users::{get_group_by_gid, get_user_by_uid};
pub fn wait_events(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    let cpus = online_cpus()?;
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("EVENT").expect(""))?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        tokio::task::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(Event::SIZE); 10];
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let event = unsafe { (buf.as_ptr() as *const Event).read_unaligned() };
                    print_event(&event, cpu);
                }
            }
        });
    }
    Ok(())
}

fn print_event(event: &Event, cpu: u32) {
    let mut table = Table::new();
    let pathname = String::from_utf8(event.path.to_vec()).unwrap_or("Unknown".to_owned());
    let user_name = match get_user_by_uid(event.uid) {
        None => format!("{}", event.uid),
        Some(name) => name.name().to_string_lossy().to_string(),
    };
    let group_name = match get_group_by_gid(event.gid) {
        None => format!("{}", event.gid),
        Some(name) => name.name().to_string_lossy().to_string(),
    };
    table.add_row(row!["cpu", "action", "user", "group", "elf"]);
    table.add_row(Row::new(vec![
        Cell::new(format!("core{}", cpu).as_str()).with_style(Attr::ForegroundColor(color::BLUE)),
        match event.denied {
            true => Cell::new("Denied").with_style(Attr::ForegroundColor(color::RED)),
            false => Cell::new("Allowed").with_style(Attr::ForegroundColor(color::GREEN)),
        },
        Cell::new(user_name.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_YELLOW)),
        Cell::new(group_name.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_YELLOW)),
        Cell::new(pathname.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_WHITE)),
    ]));
    table.printstd();
}
