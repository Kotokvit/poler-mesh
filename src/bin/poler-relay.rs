//! # poler-relay — CLI слепого маршрутизатора POLER Mesh
//!
//! Разворачивается один раз на вашем VPS:
//!
//! ```bash
//! poler-relay --init                 # конфиг + идентичность (~/.config/poler-relay/relay.toml)
//! poler-relay                        # запустить (bind + http из конфига)
//! ```
//!
//! Релей не имеет секретов для расшифровки трафика: sealed-конверты проходят
//! сквозь (docs/wire.md §4). См. docs/wire.md — полная спецификация.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "poler-relay",
    version,
    about = "poler-relay — слепой маршрутизатор POLER Mesh (свой транспорт вместо туннелей)"
)]
struct Cli {
    /// Создать конфиг с новой идентичностью (~/.config/poler-relay/relay.toml)
    #[arg(long, conflicts_with_all = ["config", "bind", "http"])]
    init: bool,

    /// Конфиг (по умолчанию ~/.config/poler-relay/relay.toml)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Переопределить client-leg bind (host:port)
    #[arg(long)]
    bind: Option<String>,

    /// Переопределить HTTP-фасад bind (host:port)
    #[arg(long)]
    http: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.init {
        return cmd_init();
    }

    let path = match config_path(cli.config.as_deref()) {
        Some(p) => p,
        None => {
            eprintln!("poler-relay: не определён HOME — укажи --config PATH");
            return ExitCode::from(2);
        }
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("poler-relay: читаю {}: {e}", path.display());
            eprintln!("poler-relay: создай конфиг: poler-relay --init");
            return ExitCode::from(2);
        }
    };
    let mut cfg = match poler_mesh::relay::RelayCfg::parse(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("poler-relay: {e}");
            return ExitCode::from(2);
        }
    };
    if let Some(b) = cli.bind {
        cfg.relay.bind = b;
    }
    if let Some(h) = cli.http {
        cfg.relay.http = h;
    }
    if cfg.clients.is_empty() {
        eprintln!(
            "poler-relay: в конфиге нет ни одного [[clients]] — link-клиенту некуда подключаться"
        );
        eprintln!("poler-relay: добавь блок из вывода `poler-mesh --init-link`");
        return ExitCode::from(2);
    }

    match poler_mesh::relay::run(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("poler-relay: {e}");
            ExitCode::from(1)
        }
    }
}

fn config_path(flag: Option<&std::path::Path>) -> Option<PathBuf> {
    if let Some(p) = flag {
        return Some(p.to_path_buf());
    }
    let home = std::env::var("HOME").ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("poler-relay")
            .join("relay.toml"),
    )
}

fn cmd_init() -> ExitCode {
    let path = match config_path(None) {
        Some(p) => p,
        None => {
            eprintln!("poler-relay: не определён HOME — некуда писать конфиг");
            return ExitCode::from(2);
        }
    };
    if path.exists() {
        eprintln!("poler-relay: {} уже существует — не трогаю", path.display());
        return ExitCode::from(1);
    }
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("poler-relay: mkdir {}: {e}", dir.display());
            return ExitCode::from(2);
        }
    }

    // идентичность релея
    let identity = poler_mesh::keys::Identity::generate();
    let identity_seed = poler_mesh::keys::b64_encode(identity.signing.as_bytes());

    // Bearer-токен для plain-режима (показываем один раз, в конфиге — sha256)
    let mut token_bytes = [0u8; 18];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut token_bytes);
    }
    let token: String = "poler_mesh_".to_string()
        + &token_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let token_hash = poler_mesh::relay::token_sha256(&token);

    let text = poler_mesh::relay::example_toml("relay-1", &identity_seed, &token_hash);
    if let Err(e) = std::fs::write(&path, text) {
        eprintln!("poler-relay: write {}: {e}", path.display());
        return ExitCode::from(2);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    println!("создан {}", path.display());
    println!();
    println!("1) Зарегистрируй link-клиент — на СВОЕЙ машине запусти:");
    println!("       poler-mesh --init-link");
    println!("   и вставь вывод (verify_key/box_key) в [[clients]] конфига релея.");
    println!("2) Зарегистрируй агента (sealed): poler_agent.py --init → [[agents]].");
    println!("3) Запусти релей:      poler-relay");
    println!("4) На своей машине:    poler-mesh --mcp-link <VPS>:8771 \\");
    println!("                          --relay-key {} \\",
        poler_mesh::keys::b64_encode(identity.signing.verifying_key().as_bytes()));
    println!("                          --agent <id>=<b64>");
    println!();
    println!("Bearer-токен plain-режима (показан ОДИН раз):");
    println!("    {token}");
    ExitCode::SUCCESS
}
