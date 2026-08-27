//! # Мок-узел — минимальный MCP stdio-сервер для тестов сетки
//!
//! `poler-mesh --mock-node demo` поднимает узел с инструментами
//! `demo_echo` и `demo_ping`. Двойная роль:
//!
//! 1. Тесты poler-mesh спавнят моки как детей хаба — сетка проверяется
//!    end-to-end без сети и без poler-git/poler-engine.
//! 2. Это живой шаблон: «как написать узел POLER Mesh» — 100 строк
//!    на любом языке, говорящем line-delimited JSON-RPC.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

/// Запустить мок-узел с данным именем. Блокируется на stdin.
pub fn run_mock_stdio(name: &str) -> i32 {
    eprintln!("mock-node[{name}]: stdio JSON-RPC (MCP), инструменты: {name}_echo, {name}_ping");
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(resp) = handle(&name, &v) else { continue };
        let Ok(s) = serde_json::to_string(&resp) else { continue };
        let _ = writeln!(out, "{s}");
        let _ = out.flush();
    }
    0
}

fn handle(name: &str, req: &Value) -> Option<Value> {
    let id = req.get("id").cloned()?;
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let result = match method {
        "initialize" => json!({
            "protocolVersion": crate::PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": format!("mock-{name}"), "version": env!("CARGO_PKG_VERSION")}
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": [
            {
                "name": format!("{name}_echo"),
                "description": format!("Эхо-тест узла {name}: возвращает текст с меткой узла."),
                "inputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"]
                }
            },
            {
                "name": format!("{name}_ping"),
                "description": format!("Пинг узла {name}."),
                "inputSchema": {"type": "object", "properties": {}}
            }
        ]}),
        "tools/call" => {
            let tool = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match tool {
                t if t == format!("{name}_echo") => {
                    let text = args
                        .get("text")
                        .and_then(|t| t.as_str())
                        .unwrap_or("(пусто)");
                    json!({
                        "content": [{"type": "text", "text": format!("[{name}] {text}")}],
                        "isError": false
                    })
                }
                t if t == format!("{name}_ping") => json!({
                    "content": [{"type": "text", "text": format!("pong от {name}")}],
                    "isError": false
                }),
                other => json!({
                    "content": [{"type": "text", "text": format!("mock[{name}]: неизвестный инструмент «{other}»")}],
                    "isError": true
                }),
            }
        }
        other => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("mock[{name}]: метод «{other}» не поддерживается")}
            }));
        }
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_advertises_mock_name() {
        let r = handle("demo", &json!({"jsonrpc":"2.0","id":1,"method":"initialize"})).unwrap();
        assert_eq!(r["result"]["serverInfo"]["name"], "mock-demo");
    }

    #[test]
    fn tools_list_has_two_tools() {
        let r = handle("a", &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "a_echo");
        assert_eq!(tools[1]["name"], "a_ping");
    }

    #[test]
    fn echo_returns_labelled_text() {
        let r = handle(
            "a",
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"a_echo","arguments":{"text":"привет"}}}),
        )
        .unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "[a] привет");
    }

    #[test]
    fn ping_pongs() {
        let r = handle(
            "b",
            &json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
                "params":{"name":"b_ping","arguments":{}}}),
        )
        .unwrap();
        assert_eq!(r["result"]["content"][0]["text"], "pong от b");
    }

    #[test]
    fn unknown_tool_is_honest_error() {
        let r = handle(
            "a",
            &json!({"jsonrpc":"2.0","id":5,"method":"tools/call",
                "params":{"name":"nope","arguments":{}}}),
        )
        .unwrap();
        assert_eq!(r["result"]["isError"], true);
    }

    #[test]
    fn notification_returns_none() {
        assert!(handle("a", &json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
    }
}
