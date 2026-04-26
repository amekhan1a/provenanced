# provenanced

## file provenance tracker

a linux daemon that watches configured directories and stamps new files with extended attributes containing the creator's executable path, pid, and a timestamp of creation

## usage

- `provenanced`: run the daemon (requires root)
- `provenance <path>`: check provenance data for <path>
- `provenance --scan <dir>`: list all stamped files in a directory

## configuration

provenanced looks for a config file at `/etc/provenanced.conf`, in which you must define a `[watch]` section with at least one directory and define how many subdirectories the daemon must watch

```toml
[watch]
dirs = [
    "/home/user/exampledirectory",
    "/home/user/anotherexampledirectory",
]

# recursive_depth must be either "ALL" or a non-negative integer, 0 to not recurse into subdirectories
# default setting is "ALL"
[options]
recursive_depth = "ALL"
```

## build

```bash
cargo build --release
```

## run

```bash
sudo ./target/release/provenanced
```

you may create a service file too or use the provided one

## notes

- linux >=5.17
- only works on filesystems that support extended attributes (like ext4, btrfs, xfs)

some short lived processes such as touch, mkdir or cp may exit too quickly for provenanced to stamp a file correctly, if that is the case, the attribute containing the executable's path will be something like this: "pid:12345:exited"

## license
GPLv3 or later, see LICENSE
