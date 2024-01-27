# Program execute black list 


## Features
- File
  - single file add
- Dir
  - dir add 

## Toolchain
- rust
- aya-tool
- bpf-linker
- xtask

## Build & Run

```
$ cargo xtask build-ebpf 
```
```
$ RUST_LOG=debug cargo xtask run -- -b /bin/ls
$ /bin/ls
```

## License

- MIT License
