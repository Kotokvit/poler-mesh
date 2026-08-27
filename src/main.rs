//! # poler-mesh — CLI

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use serde_json::{json, Value};

use poler_mesh::config::{MeshCfg, NodeCfg};
use poler_mesh::{http, hub::Hub, mock};

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
    #[arg(long, conflicts_with_all = ["mcp_http", "nodes_cmd", "init_cmd"])]
    mcp_stdio: bool,

    /// Хаб как HTTP MCP-сервер (для агента через туннель)
    #[arg(
        long,
        value_name = "BIND",
        num_args = 0..=1,
        default_missing_value = "127.0.0.1:8770",
        conflicts_with_all = ["mcp_stdio", "nodes_cmd", "init_cmd"]
    )]
    mcp_http: Option<String>,

    /// Токен доступа (env POLER_MESH_TOKEN; без — генерируется)
    #[arg(long, requires = "mcp_http")]
    mcp_token: Option<String>,

    /// Диагностика: поднять узлы, показать инструменты
    #[arg(long = "nodes", conflicts_with_all = ["mcp_stdio", "mcp_http", "init_cmd"])]
    nodes_cmd: bool,

    /// Создать пример mesh.toml (~/.config/poler-mesh/mesh.toml)
    #[arg(long = "init", conflicts_with_all = ["mcp_stdio", "mcp_http", "nodes_cmd"])]
    init_cmd: bool,

    /// (скрытый) Мок-узел для тестов сетки: stdio MCP с <name>_echo/<name>_ping
    #[arg(long, value_name = "NAME", hide = true, conflicts_with_all = ["mcp_http", "nodes_cmd", "init_cmd"])]
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

    // по умолчанию и с --mcp-stdio: хаб как stdio MCP-сервер
    run_stdio(&cfg.nodes)
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
