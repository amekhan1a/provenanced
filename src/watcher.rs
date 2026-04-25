use crate::{exe_of, stamp, RecursiveDepth};
use log::{debug, error, info, warn};
use std::ffi::OsStr;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

const INFO_FID:           u8 = 1;
const INFO_DFID_NAME:     u8 = 2;
const INFO_DFID:          u8 = 3;
const INFO_OLD_DFID_NAME: u8 = 10;
const INFO_NEW_DFID_NAME: u8 = 12;

struct Job {
    path:  PathBuf,
    pid:   i32,
    exe:   String,
    label: &'static str,
}

pub fn run(dirs: &[PathBuf], depth: RecursiveDepth) {
    let fan_fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_REPORT_DFID_NAME,
            0,
        )
    };
    if fan_fd < 0 {
        error!("watcher: fanotify_init: {}", std::io::Error::last_os_error());
        return;
    }

    let mount_fd = open_mount_fd(dirs);

    for dir in dirs {
        mark_recursive(fan_fd, dir, depth, 0);
    }

    let (tx, rx) = mpsc::sync_channel::<Job>(512);
    thread::Builder::new()
        .name("stamp-worker".into())
        .spawn(move || {
            for job in rx {
                match stamp(&job.path, job.pid, &job.exe) {
                    Ok(true)  => info!("stamped {} ({}) by {} (pid {})",
                                       job.path.display(), job.label, job.exe, job.pid),
                    Ok(false) => debug!("already stamped {}", job.path.display()),
                    Err(e)    => warn!("stamp failed for {}: {e}", job.path.display()),
                }
            }
        })
        .expect("watcher: failed to spawn stamp-worker thread");

    info!("watcher: event loop started");

    let root_dirs: Vec<PathBuf> = dirs.to_vec();

    let mut buf = vec![0u8; 8192];
    let meta_sz = mem::size_of::<libc::fanotify_event_metadata>();

    loop {
        let n = unsafe {
            libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) { continue; }
            error!("watcher: read: {e}");
            continue;
        }

        let n = n as usize;
        let mut off = 0usize;

        while off + meta_sz <= n {
            let meta = unsafe {
                &*(buf.as_ptr().add(off) as *const libc::fanotify_event_metadata)
            };
            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                error!("watcher: metadata version mismatch - kernel/libc mismatch?");
                break;
            }

            let event_end  = off + meta.event_len as usize;
            let info_start = off + meta.metadata_len as usize;

            if event_end <= n {
                handle_event(
                    &buf[info_start..event_end],
                    meta.mask, meta.pid,
                    mount_fd, fan_fd,
                    &tx,
                    &root_dirs,
                    depth,
                );
            }
            off = event_end;
        }
    }
}

fn handle_event(
    info:      &[u8],
    mask:      u64,
    pid:       i32,
    mount_fd:  libc::c_int,
    fan_fd:    libc::c_int,
    tx:        &mpsc::SyncSender<Job>,
    root_dirs: &[PathBuf],
    depth:     RecursiveDepth,
) {
    let exe = exe_of(pid);

    let hdr_sz = mem::size_of::<libc::fanotify_event_info_header>();
    let mut cur = 0usize;

    while cur + hdr_sz <= info.len() {
        let hdr = unsafe {
            &*(info.as_ptr().add(cur) as *const libc::fanotify_event_info_header)
        };
        let rec = hdr.len as usize;
        if rec < hdr_sz || cur + rec > info.len() { break; }

        match hdr.info_type {
            INFO_FID if mask & libc::FAN_CLOSE_WRITE != 0 => {
                if let Some(path) = parse_fid_path(&info[cur..cur + rec], mount_fd) {
                    enqueue(tx, Job { path, pid, exe: exe.clone(), label: "close-write" });
                }
            }

            INFO_DFID_NAME if mask & libc::FAN_CREATE != 0 => {
                if let Some(path) = parse_dfid_name_path(&info[cur..cur + rec], mount_fd) {
                    let is_dir = mask & libc::FAN_ONDIR != 0;
                    if is_dir {
                        let current = path_depth_from_roots(&path, root_dirs);
                        let within_limit = match depth {
                            RecursiveDepth::All        => true,
                            RecursiveDepth::Depth(max) => current <= max,
                        };
                        if within_limit {
                            mark_recursive(fan_fd, &path, depth, current);
                        }
                    }
                    if path.exists() {
                        let label = if is_dir { "create-dir" } else { "create" };
                        enqueue(tx, Job { path, pid, exe: exe.clone(), label });
                    }
                }
            }

            INFO_NEW_DFID_NAME if mask & libc::FAN_RENAME != 0 => {
                if let Some(path) = parse_dfid_name_path(&info[cur..cur + rec], mount_fd) {
                    if path.is_dir() {
                        let current = path_depth_from_roots(&path, root_dirs);
                        let within_limit = match depth {
                            RecursiveDepth::All        => true,
                            RecursiveDepth::Depth(max) => current <= max,
                        };
                        if within_limit {
                            mark_recursive(fan_fd, &path, depth, current);
                        }
                    }
                    if path.exists() {
                        enqueue(tx, Job { path, pid, exe: exe.clone(), label: "rename" });
                    }
                }
            }

            INFO_DFID           => {}
            INFO_OLD_DFID_NAME  => {}
            t => debug!("watcher: unknown info_type {t}"),
        }

        cur += rec;
    }
}

fn parse_fid_path(record: &[u8], mount_fd: libc::c_int) -> Option<PathBuf> {
    let base = mem::size_of::<libc::fanotify_event_info_fid>();
    if record.len() < base + 8 { return None; }
    let hbytes = u32::from_ne_bytes(record[base..base + 4].try_into().ok()?) as usize;
    let hend   = base + 8 + hbytes;
    if record.len() < hend { return None; }
    open_handle_to_path(&record[base..hend], mount_fd)
}

fn parse_dfid_name_path(record: &[u8], mount_fd: libc::c_int) -> Option<PathBuf> {
    let base = mem::size_of::<libc::fanotify_event_info_fid>();
    if record.len() < base + 9 { return None; }
    let hbytes = u32::from_ne_bytes(record[base..base + 4].try_into().ok()?) as usize;
    let hend   = base + 8 + hbytes;
    if record.len() < hend + 1 { return None; }

    let dir_path = open_handle_to_path(&record[base..hend], mount_fd)?;

    let name_raw = &record[hend..];
    let name_len = name_raw.iter().position(|&b| b == 0).unwrap_or(name_raw.len());
    if name_len == 0 { return None; }

    Some(dir_path.join(OsStr::from_bytes(&name_raw[..name_len])))
}

fn open_handle_to_path(hbuf: &[u8], mount_fd: libc::c_int) -> Option<PathBuf> {
    if hbuf.len() < 8 { return None; }
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_by_handle_at,
            mount_fd as libc::c_long,
            hbuf.as_ptr() as libc::c_long,
            (libc::O_PATH | libc::O_CLOEXEC) as libc::c_long,
        )
    };
    if fd < 0 {
        debug!("watcher: open_by_handle_at: {}", std::io::Error::last_os_error());
        return None;
    }
    let fd = fd as i32;
    let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
    unsafe { libc::close(fd); }
    path.filter(|p| !p.to_string_lossy().ends_with(" (deleted)"))
}

fn path_depth_from_roots(path: &Path, roots: &[PathBuf]) -> u32 {
    roots.iter()
        .find_map(|root| path.strip_prefix(root).ok())
        .map(|rel| rel.components().count() as u32)
        .unwrap_or(0)
}

pub fn mark_recursive(
    fan_fd:        libc::c_int,
    dir:           &Path,
    depth:         RecursiveDepth,
    current_depth: u32,
) {
    if !dir.is_dir() {
        if !dir.exists() {
            warn!("watcher: path does not exist, skipping: {}", dir.display());
        }
        return;
    }

    add_mark(fan_fd, dir);

    let should_recurse = match depth {
        RecursiveDepth::All      => true,
        RecursiveDepth::Depth(max) => current_depth < max,
    };

    if !should_recurse {
        return;
    }

    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                mark_recursive(fan_fd, &entry.path(), depth, current_depth + 1);
            }
        }
    }
}

fn add_mark(fan_fd: libc::c_int, dir: &Path) {
    let Ok(cstr) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) else {
        warn!("watcher: non-UTF-8 path, skipping: {}", dir.display());
        return;
    };

    let mask: u64 = (libc::FAN_CLOSE_WRITE
        | libc::FAN_CREATE
        | libc::FAN_ONDIR
        | libc::FAN_RENAME
        | libc::FAN_EVENT_ON_CHILD) as u64;

    let ret = unsafe {
        libc::fanotify_mark(
            fan_fd,
            libc::FAN_MARK_ADD | libc::FAN_MARK_ONLYDIR,
            mask,
            libc::AT_FDCWD,
            cstr.as_ptr(),
        )
    };
    if ret < 0 {
        error!("watcher: fanotify_mark {}: {}",
               dir.display(), std::io::Error::last_os_error());
    } else {
        info!("watcher: watching {}", dir.display());
    }
}

fn open_mount_fd(dirs: &[PathBuf]) -> libc::c_int {
    for dir in dirs {
        if let Ok(cs) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) {
            let fd = unsafe {
                libc::open(cs.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
            };
            if fd >= 0 {
                info!("watcher: mount_fd opened from {}", dir.display());
                return fd;
            }
        }
    }
    warn!("watcher: all watch dirs unavailable, falling back to / for mount_fd");
    unsafe {
        libc::open(
            b"/\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    }
}

fn enqueue(tx: &mpsc::SyncSender<Job>, job: Job) {
    if let Err(mpsc::TrySendError::Full(_)) = tx.try_send(job) {
        warn!("watcher: stamp queue full – xattr worker is falling behind");
    }
}
