use serde::{Deserialize, Deserializer};
use serde::de::{self, Visitor};
use std::fmt;
use std::path::PathBuf;

// xattr namespace "user." prefix is mandatory per kernel rules
pub const XATTR_CREATED_BY:  &str = "user.provenance.created_by";
pub const XATTR_CREATED_AT:  &str = "user.provenance.created_at";
pub const XATTR_CREATOR_PID: &str = "user.provenance.creator_pid";

#[derive(Debug, Clone, Copy)]
pub enum RecursiveDepth {
    All,
    Depth(u32),
}

impl Default for RecursiveDepth {
    fn default() -> Self {
        RecursiveDepth::All
    }
}

impl fmt::Display for RecursiveDepth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecursiveDepth::All      => write!(f, "ALL"),
            RecursiveDepth::Depth(n) => write!(f, "{n}"),
        }
    }
}

struct RecursiveDepthVisitor;

impl<'de> Visitor<'de> for RecursiveDepthVisitor {
    type Value = RecursiveDepth;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the string \"ALL\" or a non-negative integer")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if v == "ALL" {
            Ok(RecursiveDepth::All)
        } else {
            Err(E::custom(format!(
                "expected \"ALL\" or a non-negative integer, got {:?}", v
            )))
        }
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        u32::try_from(v)
            .map(RecursiveDepth::Depth)
            .map_err(|_| E::custom(format!("depth must be in 0..=4294967295, got {v}")))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        u32::try_from(v)
            .map(RecursiveDepth::Depth)
            .map_err(|_| E::custom(format!("depth must be in 0..=4294967295, got {v}")))
    }
}

impl<'de> Deserialize<'de> for RecursiveDepth {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(RecursiveDepthVisitor)
    }
}

// config
#[derive(Debug, Deserialize)]
pub struct Config {
    pub watch:   WatchConfig,
    #[serde(default)]
    pub options: OptionsConfig,
}

#[derive(Debug, Deserialize)]
pub struct WatchConfig {
    pub dirs: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct OptionsConfig {
    #[serde(default)]
    pub recursive_depth: RecursiveDepth,
}

impl Default for OptionsConfig {
    fn default() -> Self {
        OptionsConfig { recursive_depth: RecursiveDepth::default() }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("config parse error: {e}"))
    }
}

pub fn stamp(path: &std::path::Path, pid: i32, exe: &str) -> Result<bool, String> {
    if xattr::get(path, XATTR_CREATED_BY).ok().flatten().is_some() {
        return Ok(false); // already stamped, so preserve original
    }
    let ts = chrono::Utc::now().to_rfc3339();
    xattr::set(path, XATTR_CREATED_BY,  exe.as_bytes())
        .map_err(|e| format!("xattr set created_by: {e}"))?;
    xattr::set(path, XATTR_CREATED_AT,  ts.as_bytes())
        .map_err(|e| format!("xattr set created_at: {e}"))?;
    xattr::set(path, XATTR_CREATOR_PID, pid.to_string().as_bytes())
        .map_err(|e| format!("xattr set creator_pid: {e}"))?;
    Ok(true)
}

/// short-lived processes (such as touch, mkdir, cp) often exit before the fanotify
/// event is drained from the queue, try following:
///
/// 1. `/proc/{pid}/exe` works while the process is alive or zombie
/// 2. `/proc/{pid}/comm` the 15-char task name that survives a tiny bit longer and is readable for zombies too
/// 3. plain `pid:{pid}:exited` label as a last resort
pub fn exe_of(pid: i32) -> String {
    // attempt 1: full executable path
    if let Ok(p) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        let s = p.to_string_lossy().into_owned();
        return s.strip_suffix(" (deleted)")
            .map(|s| format!("{s} [deleted]"))
            .unwrap_or(s);
    }
    // attempt 2: comm (process name, ≤15 chars, no path)
    if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        let comm = comm.trim();
        if !comm.is_empty() {
            return format!("{comm} (short-lived, pid {pid})");
        }
    }
    // attempt 3: give up
    format!("pid:{pid}:exited")
}

pub mod watcher;
