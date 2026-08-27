//! # Конфигурация poler-mesh (mesh.toml)
//!
//! ```toml
//! # ~/.config/poler-mesh/mesh.toml
//! [[node]]
//! id = "git"
//! cmd = "poler-git"
//! args = ["--mcp-stdio"]
//!
//! [[node]]
//! id = "engine"
//! cmd = "poler-engine"
//! args = ["--mcp"]
//! ```
//!
//! Приоритет: `--config PATH` > `~/.config/poler-mesh/mesh.toml`
//! > автопоиск poler-git/poler-engine в PATH (честный список того,
//! что реально найдено).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Один узел сетки.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCfg {
    /// Короткое имя узла (для диагностики и конфликтов).
    pub id: String,
    /// Исполняемый файл (ищется в PATH; можно абсолютный путь).
    pub cmd: String,
    /// Аргументы запуска MCP stdio-режима.
    #[serde(default)]
    pub args: Vec<String>,
}

/// Конфиг целиком.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MeshCfg {
    #[serde(default, rename = "node")]
    pub nodes: Vec<NodeCfg>,
}

impl MeshCfg {
    /// Загрузить конфиг: `--config` → дефолтный файл → автопоиск.
    pub fn load(explicit: Option<&Path>) -> Result<MeshCfg, String> {
        if let Some(p) = explicit {
            return Self::read_file(p);
        }
        if let Some(p) = Self::default_path() {
            if p.exists() {
                return Self::read_file(&p);
            }
        }
        let auto = autodiscover();
        if auto.is_empty() {
            return Err(format!(
                "узлы не найдены. Создай {} (пример: `poler-mesh init`) \
                 или укажи --config",
                Self::default_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "mesh.toml".into())
            ));
        }
        Ok(MeshCfg { nodes: auto })
    }

    /// `~/.config/poler-mesh/mesh.toml` (или `$XDG_CONFIG_HOME`).
    pub fn default_path() -> Option<PathBuf> {
        let base = match std::env::var("XDG_CONFIG_HOME") {
            Ok(v) if !v.trim().is_empty() && v.starts_with('/') => PathBuf::from(v),
            _ => PathBuf::from(std::env::var("HOME").ok()?).join(".config"),
        };
        Some(base.join("poler-mesh").join("mesh.toml"))
    }

    fn read_file(p: &Path) -> Result<MeshCfg, String> {
        let raw = std::fs::read_to_string(p)
            .map_err(|e| format!("mesh.toml {}: {e}", p.display()))?;
        let cfg: MeshCfg = toml::from_str(&raw)
            .map_err(|e| format!("mesh.toml {}: parse: {e}", p.display()))?;
        if cfg.nodes.is_empty() {
            return Err(format!("mesh.toml {}: нет ни одного [[node]]", p.display()));
        }
        Ok(cfg)
    }
}

/// Автопоиск стандартных узлов в PATH (+ ~/.local/bin, ~/.cargo/bin).
pub fn autodiscover() -> Vec<NodeCfg> {
    let mut out = Vec::new();
    let presets = [
        ("git", "poler-git", vec!["--mcp-stdio"]),
        ("engine", "poler-engine", vec!["--mcp"]),
    ];
    for (id, bin, args) in presets {
        if find_bin(bin).is_some() {
            out.push(NodeCfg {
                id: id.into(),
                cmd: bin.into(),
                args: args.into_iter().map(String::from).collect(),
            });
        }
    }
    out
}

/// Найти бинарник в PATH и типичных локальных каталогах.
pub fn find_bin(bin: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(&home).join(".local").join("bin"));
        dirs.push(PathBuf::from(&home).join(".cargo").join("bin"));
    }
    dirs.into_iter().find(|d| d.join(bin).is_file())
}

/// Содержимое примера конфига (для `poler-mesh init`).
pub fn example_toml() -> String {
    r#"# POLER Mesh — узлы сети.
# Каждый узел — отдельная программа, говорящая на MCP (stdio JSON-RPC).
# Хаб объединяет их инструменты под один токен POLER_MESH_TOKEN.

[[node]]
id = "git"
cmd = "poler-git"
args = ["--mcp-stdio"]

[[node]]
id = "engine"
cmd = "poler-engine"
args = ["--mcp"]

# Будущие узлы — тем же паттерном:
# [[node]]
# id = "mail"
# cmd = "poler-mail"
# args = ["--mcp-stdio"]
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_two_nodes() {
        let cfg: MeshCfg = toml::from_str(&example_toml()).unwrap();
        assert_eq!(cfg.nodes.len(), 2);
        assert_eq!(cfg.nodes[0].id, "git");
        assert_eq!(cfg.nodes[0].cmd, "poler-git");
        assert_eq!(cfg.nodes[0].args, vec!["--mcp-stdio"]);
        assert_eq!(cfg.nodes[1].args, vec!["--mcp"]);
    }

    #[test]
    fn empty_nodes_rejected_at_load() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("mesh.toml");
        std::fs::write(&p, "# только комментарий\n").unwrap();
        let err = MeshCfg::read_file(&p).unwrap_err();
        assert!(err.contains("нет ни одного"), "{err}");
    }

    #[test]
    fn missing_file_is_clear_error() {
        let err = MeshCfg::read_file(Path::new("/nonexistent/mesh.toml")).unwrap_err();
        assert!(err.contains("mesh.toml"), "{err}");
    }

    #[test]
    fn find_bin_finds_itself_in_tests() {
        // cargo кладёт тестовый бинарник в target/… — сам poler-mesh
        // в PATH может не быть; проверяем честное поведение на ls/cat.
        let found = find_bin("ls").or_else(|| find_bin("dir"));
        assert!(found.is_some(), "ls/dir должен найтись в PATH");
        assert!(find_bin("definitely-not-a-bin-xyz").is_none());
    }
}
