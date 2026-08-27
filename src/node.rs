//! # Дочерний узел сетки — MCP-клиент поверх stdio
//!
//! Хаб спавнит узел (`poler-git --mcp-stdio`, `poler-engine --mcp`, …)
//! и говорит с ним line-delimited JSON-RPC 2.0 — тот же транспорт,
//! что у всех узлов POLER. Никакой сети между хабом и узлами:
//! пайпы ОС, ноль открытых портов.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

/// Живой дочерний процесс-узел.
pub struct ChildNode {
    pub id: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    /// Имя сервера из initialize (для диагностики).
    pub server_name: String,
}

impl ChildNode {
    /// Спавнить узел. stderr узла наследуется — его логи видны
    /// в консоли хаба (честность вместо молчаливых сбоев).
    pub fn spawn(id: &str, cmd: &str, args: &[String]) -> Result<ChildNode, String> {
        let mut child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("не удалось запустить «{cmd}» (args {:?}): {e}", args))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("узел «{id}»: нет stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("узел «{id}»: нет stdout"))?;
        Ok(ChildNode {
            id: id.to_string(),
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 0,
            server_name: String::new(),
        })
    }

    /// Отправить запрос и дождаться ответа с совпадающим id.
    /// Уведомления от узла (например, tools/list_changed) пропускаются.
    pub fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        let msg = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        self.write_line(&msg)?;
        loop {
            let line = self
                .read_line()
                .map_err(|e| format!("узел «{}» умер или молчит: {e}", self.id))?;
            let v: Value = serde_json::from_str(&line)
                .map_err(|e| format!("узел «{}»: мусор в stdout: {e}: {line:.80}", self.id))?;
            if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
                if let Some(err) = v.get("error") {
                    let msg = err
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("без сообщения");
                    return Err(format!("узел «{}»: {msg}", self.id));
                }
                return Ok(v.get("result").cloned().unwrap_or(Value::Null));
            }
            // не наш ответ (уведомление) — игнорируем, ждём дальше
        }
    }

    /// Уведомление (без id, ответа не ждём).
    pub fn notify(&mut self, method: &str) -> Result<(), String> {
        let msg = json!({"jsonrpc":"2.0","method":method});
        self.write_line(&msg)
    }

    fn write_line(&mut self, msg: &Value) -> Result<(), String> {
        let line = serde_json::to_string(msg).map_err(|e| e.to_string())?;
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|e| format!("узел «{}»: stdin: {e}", self.id))
    }

    fn read_line(&mut self) -> Result<String, String> {
        let mut buf = String::new();
        let n = self
            .stdout
            .read_line(&mut buf)
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("EOF (процесс закрыл stdout)".into());
        }
        let t = buf.trim().to_string();
        if t.is_empty() {
            // пустая строка между сообщениями — читаем дальше
            return self.read_line();
        }
        Ok(t)
    }

    /// Рукопожатие MCP: initialize + notifications/initialized.
    pub fn initialize(&mut self) -> Result<Value, String> {
        let result = self.request(
            "initialize",
            json!({
                "protocolVersion": crate::PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "poler-mesh",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )?;
        self.notify("notifications/initialized")?;
        self.server_name = result
            .pointer("/serverInfo/name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        Ok(result)
    }

    /// tools/list узла.
    pub fn tools(&mut self) -> Result<Vec<Value>, String> {
        let r = self.request("tools/list", json!({}))?;
        Ok(r.get("tools")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// tools/call — прямая передача.
    pub fn call_tool(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        self.request("tools/call", json!({"name": name, "arguments": args}))
    }

    /// Жив ли ещё процесс.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for ChildNode {
    fn drop(&mut self) {
        // не оставляем сирот: kill закрывает пайпы, узел завершается
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Чистая функция маршрутизации: (id узла, имена инструментов) → карта
/// имя→индекс узла + список конфликтов (имя, первый узел, второй узел).
/// Выделена отдельно, чтобы тестировать без спавна процессов.
pub fn build_route(
    lists: &[(String, Vec<String>)],
) -> (HashMap<String, usize>, Vec<(String, String, String)>) {
    let mut route: HashMap<String, usize> = HashMap::new();
    let mut conflicts = Vec::new();
    for (i, (id, names)) in lists.iter().enumerate() {
        for name in names {
            if name.is_empty() {
                continue;
            }
            if let Some(&first) = route.get(name) {
                conflicts.push((name.clone(), lists[first].0.clone(), id.clone()));
                continue;
            }
            route.insert(name.clone(), i);
        }
    }
    (route, conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_without_conflicts() {
        let lists = vec![
            ("git".into(), vec!["a".into(), "b".into()]),
            ("engine".into(), vec!["c".into()]),
        ];
        let (route, conflicts) = build_route(&lists);
        assert_eq!(route.len(), 3);
        assert_eq!(route["a"], 0);
        assert_eq!(route["c"], 1);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn route_conflict_first_node_wins() {
        let lists = vec![
            ("one".into(), vec!["dup".into(), "x".into()]),
            ("two".into(), vec!["dup".into()]),
        ];
        let (route, conflicts) = build_route(&lists);
        assert_eq!(route["dup"], 0, "первый узел держит имя");
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0], ("dup".into(), "one".into(), "two".into()));
    }

    #[test]
    fn route_empty_names_skipped() {
        let lists = vec![("n".into(), vec![String::new(), "ok".into()])];
        let (route, _) = build_route(&lists);
        assert_eq!(route.len(), 1);
        assert!(route.contains_key("ok"));
    }
}
