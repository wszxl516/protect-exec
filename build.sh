#!/bin/sh
if [ ! -f "protect-ebpf/src/vmlinuz.rs" ]; then
    echo "generate vmlinuz.rs"
    aya-tool generate linux_binprm task_stuct dentry kernel_siginfo -- -o protect-ebpf/src/vmlinuz.rs
fi
cd protect-ebpf
cargo b -r -p protect-ebpf
cd ..
cargo b -p protect
export RUST_LOG=debug 
sudo -E ./target/debug/protect $@
