use std::path::{Path, PathBuf};
use provenanced::{XATTR_CREATED_AT, XATTR_CREATED_BY, XATTR_CREATOR_PID};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.as_slice() {
        [_, flag, dir] if flag == "--scan" => scan(Path::new(dir)),

        // unknown flags (with or without trailing arguments)
        [_, flag, ..] if flag.starts_with("--") => {
            eprintln!("error: unknown flag: {flag}");
            eprintln!("Usage:\n  provenance <path>\n  provenance --scan <dir>");
            std::process::exit(1);
        }

        // no arguments
        [_] => {
            eprintln!("Usage:\n  provenance <path>\n  provenance --scan <dir>");
            std::process::exit(1);
        }

        // single positional argument: treat as a path to inspect
        [_, path] => show_one(Path::new(path)),

        // anything else: too many arguments
        _ => {
            eprintln!("error: too many arguments");
            eprintln!("Usage:\n  provenance <path>\n  provenance --scan <dir>");
            std::process::exit(1);
        }
    }
}

fn read_xattr(path: &Path, name: &str) -> Option<String> {
    xattr::get(path, name).ok().flatten().and_then(|v| String::from_utf8(v).ok())
}

fn show_one(path: &Path) {
    if !path.exists() {
        eprintln!("No such path: {}", path.display());
        std::process::exit(1);
    }

    let created_by  = read_xattr(path, XATTR_CREATED_BY);
    let created_at  = read_xattr(path, XATTR_CREATED_AT);
    let creator_pid = read_xattr(path, XATTR_CREATOR_PID);

    if created_by.is_none() {
        println!(
            "{}: no provenance stamp: file either predates provenanced or filesystem doesn't support xattrs",
            path.display()
        );
        return;
    }

    println!("{}", path.display());
    if let Some(v) = created_by  { println!("  created_by  : {v}"); }
    if let Some(v) = created_at  { println!("  created_at  : {v}"); }
    if let Some(v) = creator_pid { println!("  creator_pid : {v}"); }
}

fn scan(dir: &Path) {
    if !dir.is_dir() {
        eprintln!("Not a directory: {}", dir.display());
        std::process::exit(1);
    }

    println!("Stamped entries under {}:\n", dir.display());

    let mut count = 0usize;
    for p in walk(dir) {
        let Some(by) = read_xattr(&p, XATTR_CREATED_BY) else { continue };
        let at  = read_xattr(&p, XATTR_CREATED_AT).unwrap_or_default();
        let pid = read_xattr(&p, XATTR_CREATOR_PID).unwrap_or_default();

        println!("  {}", p.display());
        println!("    created_by  : {by}");
        println!("    created_at  : {at}");
        println!("    creator_pid : {pid}");
        count += 1;
    }

    println!("\n{count} stamped entries");
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(walk(&p));
        }
        out.push(p);
    }
    out
}
