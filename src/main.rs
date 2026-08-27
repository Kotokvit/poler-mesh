//! # poler-mesh — CLI

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use serde_json::{json, Value};

use poler_mesh::config::{MeshCfg, NodeCfg};
use poler_mesh::keys::Identity;
use poler_mesh::{http, hub::Hub, link, mock};

#[derive(Parser, Debug)]
#[command(
    name = "poler-mesh",
    version,
    about = "POLER Mesh hub — единый MCP-диспетчер: один токен → вся экосистема",
    long_about = "poler-mesh объединяет узлы POLER-сети (poler-git, poler-engine, будущие \
почта/диск) под один MCP-интерфейс. Каждый узел — отдельная программа, говорящая \
line-delimited JSON-RPC по stdio. Хаб спавнит узлы, объединяет их tools/list и \
маршрутизует tools/call. Один POLER_MESH_TOKEN даёт агенту доступ ко всему."
)]
struct Cli {
    /// mesh.toml с узлами (по умолчанию ~/.config/poler-mesh/mesh.toml,
    /// иначе автопоиск poler-git/poler-engine в PATH)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Хаб как stdio MCP-сервер (для вызова из другого CLI)
    #[arg(long, conflicts_with_all = ["mcp_http", "nodes_cmd", "init_cmd", "mcp_link", "init_link"])]
    mcp_stdio: bool,

    /// Хаб как HTTP MCP-сервер (для агента через туннель)
    #[arg(
        long,
        value_name = "BIND",
        num_args = 0..=1,
        default_missing_value = "127.0.0.1:8770",
        conflicts_with_all = ["mcp_stdio", "nodes_cmd", "init_cmd", "mcp_link", "init_link"]
    )]
    mcp_http: Option<String>,

    /// Хаб подключается ИСХОДЯЩИМ каналом к poler-relay — замена туннеля
    /// (env POLER_LINK_ADDR; docs/wire.md)
    #[arg(
        long,
        value_name = "HOST:PORT",
        conflicts_with_all = ["mcp_stdio", "mcp_http", "nodes_cmd", "init_cmd", "init_link"]
    )]
    mcp_link: Option<String>,

    /// Файл идентичности link-клиента (env POLER_LINK_IDENTITY;
    /// по умолчанию ~/.config/poler-mesh/link-identity.json)
    #[arg(long, value_name = "PATH", requires = "mcp_link")]
    link_identity: Option<PathBuf>,

    /// Публичный Ed25519-ключ релея (b64) — пиннинг против MITM (env POLER_RELAY_KEY)
    #[arg(long, value_name = "B64", requires = "mcp_link")]
    relay_key: Option<String>,

    /// Доверенный агент: ID=B64 (можно несколько раз; env POLER_LINK_AGENTS "id=b64,id=b64")
    #[arg(long, value_name = "ID=B64", requires = "mcp_link")]
    agent: Vec<String>,

    /// Токен доступа (env POLER_MESH_TOKEN; без — генерируется)
    #[arg(long, requires = "mcp_http")]
    mcp_token: Option<String>,

    /// Диагностика: поднять узлы, показать инструменты
    #[arg(long = "nodes", conflicts_with_all = ["mcp_stdio", "mcp_http", "init_cmd", "mcp_link", "init_link"])]
    nodes_cmd: bool,

    /// Создать пример mesh.toml (~/.config/poler-mesh/mesh.toml)
    #[arg(long = "init", conflicts_with_all = ["mcp_stdio", "mcp_http", "nodes_cmd", "mcp_link", "init_link"])]
    init_cmd: bool,

    /// Сгенерировать идентичность link-клиента + показать конфиг для poler-relay
    #[arg(long, conflicts_with_all = ["mcp_stdio", "mcp_http", "nodes_cmd", "init_cmd", "mcp_link"])]
    init_link: bool,

    /// (скрытый) Мок-узел для тестов сетки: stdio MCP с <name>_echo/<name>_ping
    #[arg(long, value_name = "NAME", hide = true, conflicts_with_all = ["mcp_http", "nodes_cmd", "init_cmd", "mcp_link", "init_link"])]
    mock_node: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // мок-режим: сам становлюсь узлом (используется тестами и как шаблон)
    if let Some(name) = &cli.mock_node {
        return ExitCode::from(mock::run_mock_stdio(name) as u8);
    }

    if cli.init_cmd {
        return cmd_init();
    }

    if cli.init_link {
        return cmd_init_link();
    }

    let cfg = match MeshCfg::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("poler-mesh: {e}");
            return ExitCode::from(2);
        }
    };

    if cli.nodes_cmd {
        return cmd_nodes(&cfg);
    }

    if let Some(bind) = &cli.mcp_http {
        let token = cli
            .mcp_token
            .clone()
            .or_else(|| std::env::var("POLER_MESH_TOKEN").ok().filter(|t| !t.trim().is_empty()))
            .unwrap_or_else(http::generate_token);
        let code = http::run_http(bind, &token, &cfg.nodes);
        return ExitCode::from(code as u8);
    }

    if let Some(addr) = &cli.mcp_link {
        return cmd_link(&cli, addr, &cfg);
    }

    // по умолчанию и с --mcp-stdio: хаб как stdio MCP-сервер
    run_stdio(&cfg.nodes)
}

/// --mcp-link: исходящий канал к poler-relay (замена туннеля).
fn cmd_link(cli: &Cli, addr: &str, cfg: &MeshCfg) -> ExitCode {
    let identity_path = cli
        .link_identity
        .clone()
        .or_else(|| std::env::var("POLER_LINK_IDENTITY").ok().map(PathBuf::from))
        .or_else(|| {
            std::env::var("HOME").ok().map(|h| {
                PathBuf::from(h)
                    .join(".config")
                    .join("poler-mesh")
                    .join("link-identity.json")
            })
        });
    let identity_path = match identity_path {
        Some(p) => p,
        None => {
            eprintln!("poler-mesh-link: не найден файл идентичности — запусти poler-mesh --init-link");
            return ExitCode::from(2);
        }
    };
    let text = match std::fs::read_to_string(&identity_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "poler-mesh-link: читаю {}: {e} (создать: poler-mesh --init-link)",
                identity_path.display()
            );
            return ExitCode::from(2);
        }
    };
    let identity = match Identity::from_json(&text) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("poler-mesh-link: {}: {e}", identity_path.display());
            return ExitCode::from(2);
        }
    };
    let relay_key = cli
        .relay_key
        .clone()
        .or_else(|| std::env::var("POLER_RELAY_KEY").ok())
        .unwrap_or_default();
    if relay_key.trim().is_empty() {
        eprintln!("poler-mesh-link: обязателен --relay-key <b64> (пиннинг ключа релея, вывод poler-relay --init)");
        return ExitCode::from(2);
    }
    let relay_verify = match poler_mesh::keys::verify_key_from_b64(&relay_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("poler-mesh-link: --relay-key: {e}");
            return ExitCode::from(2);
        }
    };
    let mut agent_specs = cli.agent.clone();
    if agent_specs.is_empty() {
        if let Ok(env_specs) = std::env::var("POLER_LINK_AGENTS") {
            agent_specs.push(env_specs);
        }
    }
    let trusted_agents = match link::parse_trusted_agents(&agent_specs) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("poler-mesh-link: --agent: {e}");
            return ExitCode::from(2);
        }
    };
    if trusted_agents.is_empty() {
        eprintln!("poler-mesh-link: нет доверенных агентов (--agent ID=B64) — sealed-режим будет отклонять запросы");
    }
    let opts = link::LinkOpts {
        addr: addr.to_string(),
        identity,
        client_id: "main".to_string(),
        relay_verify,
        trusted_agents,
    };
    let code = link::run_link(opts, &cfg.nodes);
    ExitCode::from(code as u8)
}

/// --init-link: сгенерировать идентичность и показать конфиг для релея/агентов.
fn cmd_init_link() -> ExitCode {
    let path = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h)
            .join(".config")
            .join("poler-mesh")
            .join("link-identity.json"),
        Err(_) => {
            eprintln!("poler-mesh: не определён HOME — некуда писать идентичность");
            return ExitCode::from(2);
        }
    };
    if path.exists() {
        eprintln!("poler-mesh: {} уже существует — не трогаю", path.display());
        return ExitCode::from(1);
    }
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("poler-mesh: mkdir {}: {e}", dir.display());
            return ExitCode::from(2);
        }
    }
    let identity = Identity::generate();
    if let Err(e) = std::fs::write(&path, identity.to_json()) {
        eprintln!("poler-mesh: write {}: {e}", path.display());
        return ExitCode::from(2);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    println!("создана идентичность: {} (права 600)", path.display());
    println!();
    println!("Вставь в relay.toml (на VPS) блок клиента:");
    println!("  [[clients]]");
    println!("  id = \"main\"");
    println!("  verify_key = \"{}\"", identity.verify_key_b64());
    println!("  box_key = \"{}\"", identity.box_public_b64());
    println!();
    println!("Выдай доверенным агентам (вместе с ключом релея):");
    println!("  box_key    = \"{}\"", identity.box_public_b64());
    println!("  verify_key = \"{}\"", identity.verify_key_b64());
    println!();
    println!("Их ключ (verify_key) верни себе и укажи при запуске:");
    println!("  poler-mesh --mcp-link <VPS>:8771 \\");
    println!("      --relay-key <ключ релея> \\");
    println!("      --agent glm=<verify_key агента>");
    ExitCode::SUCCESS
}

fn cmd_init() -> ExitCode {
    let path = match MeshCfg::default_path() {
        Some(p) => p,
        None => {
            eprintln!("poler-mesh: не определён HOME — некуда писать конфиг");
            return ExitCode::from(2);
        }
    };
    if path.exists() {
        eprintln!("poler-mesh: {} уже существует — не трогаю", path.display());
        return ExitCode::from(1);
    }
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("poler-mesh: mkdir {}: {e}", dir.display());
            return ExitCode::from(2);
        }
    }
    if let Err(e) = std::fs::write(&path, poler_mesh::config::example_toml()) {
        eprintln!("poler-mesh: write {}: {e}", path.display());
        return ExitCode::from(2);
    }
    println!("создан {}", path.display());
    println!("отредактируй список узлов и запусти: poler-mesh nodes");
    ExitCode::SUCCESS
}

fn cmd_nodes(cfg: &MeshCfg) -> ExitCode {
    println!("POLER Mesh — узлы:");
    for n in &cfg.nodes {
        println!("  {:<12} {:?} {:?}", n.id, n.cmd, n.args);
    }
    println!();
    match Hub::build(&cfg.nodes) {
        Ok(hub) => {
            println!("статус:");
            for line in hub.status_lines() {
                println!("{line}");
            }
            println!();
            let names = hub.tool_names();
            println!("инструменты ({}):", names.len());
            let mut sorted = names;
            sorted.sort();
            for n in sorted {
                println!("  {n}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("poler-mesh: {e}");
            ExitCode::from(1)
        }
    }
}

/// Хаб как stdio MCP-сервер: line-delimited JSON-RPC на stdin/stdout.
fn run_stdio(nodes_cfg: &[NodeCfg]) -> ExitCode {
    let mut hub = match Hub::build(nodes_cfg) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("poler-mesh: {e}");
            return ExitCode::from(2);
        }
    };
    eprintln!(
        "poler-mesh: stdio JSON-RPC (MCP) — {} инструментов, {} узл(ов)",
        hub.tools.len(),
        hub.nodes.len()
    );
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            let resp = json!({
                "jsonrpc":"2.0","id":Value::Null,
                "error":{"code":-32700,"message":"poler-mesh: не JSON"}
            });
            let _ = writeln!(out, "{}", serde_json::to_string(&resp).unwrap_or_default());
            let _ = out.flush();
            continue;
        };
        if let Some(resp) = hub.dispatch(&v) {
            let _ = writeln!(out, "{}", serde_json::to_string(&resp).unwrap_or_default());
            let _ = out.flush();
        }
    }
    ExitCode::SUCCESS
}
