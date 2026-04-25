use provenanced::Config;

const CONFIG_PATH: &str = "/etc/provenanced.conf";

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    ).init();

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("provenanced must run as root!");
        std::process::exit(1);
    }

    let config = Config::load(CONFIG_PATH).unwrap_or_else(|e| {
        eprintln!("config error: {e}");
        std::process::exit(1);
    });

    if config.watch.dirs.is_empty() {
        eprintln!("no directories configured in [watch] dirs");
        std::process::exit(1);
    }

    log::info!("provenanced v{} starting", env!("CARGO_PKG_VERSION"));
    log::info!("{} top-level watch dir(s), recursive_depth = {}",
               config.watch.dirs.len(),
               config.options.recursive_depth);

    provenanced::watcher::run(&config.watch.dirs, config.options.recursive_depth);

    log::error!("watcher exited unexpectedly");
    std::process::exit(1);
}
