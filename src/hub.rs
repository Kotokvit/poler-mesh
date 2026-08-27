//! # Хаб — реестр узлов, объединение инструментов, маршрутизация вызовов
//!
//! `Hub::build` поднимает все узлы из конфига, делает MCP-рукопожатие,
//! собирает tools/list каждого и строит карту «имя инструмента → узел».
//! Конфликт имён решается честно: первый узел держит имя, конфликт
//! фиксируется и репортится (анти-p3: ничего тихого).

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::config::NodeCfg;
use crate::node::{build_route, ChildNode};

pub struct Hub {
    pub nodes: Vec<ChildNode>,
    /// Объединённый tools/list (кэш; refresh_tools() пересобирает).
    pub tools: Vec<Value>,
    /// имя инструмента → индекс узла.
    route: HashMap<String, usize>,
    /// (имя, узел-хозяин, узел-дубликат).
    pub conflicts: Vec<(String, String, String)>,
}

impl Hub {
    /// Поднять все узлы, инициализировать, собрать инструменты.
    /// Ошибка любого узла — честная ошибка всего старта (fail-fast):
    /// пользователь видит сразу, что не так, а не «куда-то пропавший»
    /// инструмент посреди работы.
    pub fn build(nodes_cfg: &[NodeCfg]) -> Result<Hub, String> {
        if nodes_cfg.is_empty() {
            return Err("конфиг пуст: ни одного узла".into());
        }
        let mut nodes = Vec::new();
        for n in nodes_cfg {
            eprintln!("poler-mesh: поднимаю узел «{}» ({:?})…", n.id, n.cmd);
            let mut c = ChildNode::spawn(&n.id, &n.cmd, &n.args)
                .map_err(|e| format!("узел «{}»: {e}", n.id))?;
            c.initialize()
                .map_err(|e| format!("узел «{}» не инициализировался: {e}", n.id))?;
            eprintln!("poler-mesh: узел «{}» = {} — ок", n.id, c.server_name);
            nodes.push(c);
        }
        let mut hub = Hub {
            nodes,
            tools: Vec::new(),
            route: HashMap::new(),
            conflicts: Vec::new(),
        };
        hub.refresh_tools()?;
        for (name, owner, dup) in &hub.conflicts {
            eprintln!(
                "poler-mesh: ВНИМАНИЕ: инструмент «{name}» объявлен и у «{owner}», и у «{dup}»; обслуживает «{owner}»"
            );
        }
        eprintln!(
            "poler-mesh: сетка готова: {} узл(ов), {} инструментов",
            hub.nodes.len(),
            hub.tools.len()
        );
        Ok(hub)
    }

    /// Пересобрать объединённый список инструментов из всех узлов.
    pub fn refresh_tools(&mut self) -> Result<(), String> {
        // 1) спросить каждый узел
        let mut collected: Vec<(String, Vec<Value>)> = Vec::new();
        for n in self.nodes.iter_mut() {
            let tools = n
                .tools()
                .map_err(|e| format!("узел «{}»: tools/list: {e}", n.id))?;
            collected.push((n.id.clone(), tools));
        }
        // 2) карта маршрутизации по именам
        let lists: Vec<(String, Vec<String>)> = collected
            .iter()
            .map(|(id, ts)| {
                (
                    id.clone(),
                    ts.iter()
                        .filter_map(|t| t.get("name").and_then(|v| v.as_str()).map(String::from))
                        .collect(),
                )
            })
            .collect();
        let (route, conflicts) = build_route(&lists);
        self.route = route;
        self.conflicts = conflicts;
        // 3) собрать описания (первое вхождение имени побеждает)
        let mut tools = Vec::new();
        let mut seen: HashMap<String, ()> = HashMap::new();
        for (id, list) in collected {
            for t in list {
                let name = t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() || seen.contains_key(&name) {
                    continue;
                }
                seen.insert(name.clone(), ());
                // помечаем происхождение — агент видит, откуда инструмент
                let mut t = t;
                if let Some(obj) = t.as_object_mut() {
                    obj.insert("_mesh_node".into(), json!({ "id": id }));
                }
                tools.push(t);
            }
        }
        self.tools = tools;
        Ok(())
    }

    /// Диспетчер JSON-RPC: единая точка входа для stdio и HTTP.
    /// None → уведомление (ответа не требуется).
    pub fn dispatch(&mut self, req: &Value) -> Option<Value> {
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let id = id?;

        let outcome: Result<Value, String> = match method {
            "initialize" => Ok(json!({
                "protocolVersion": crate::PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {
                    "name": "poler-mesh",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": self.tools})),
            "tools/call" => self.dispatch_call(&params),
            other => Err(format!(
                "poler-mesh: метод «{other}» не поддерживается (v0.1: initialize | ping | tools/list | tools/call)"
            )),
        };

        Some(match outcome {
            Ok(r) => json!({"jsonrpc":"2.0","id":id,"result":r}),
            Err(e) => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":e}}),
        })
    }

    fn dispatch_call(&mut self, params: &Value) -> Result<Value, String> {
        let name = params
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        match self.route.get(&name) {
            Some(&i) => self.nodes[i].call_tool(&name, &args).map_err(|e| e.to_string()),
            None => {
                let known: Vec<String> = self.route.keys().cloned().collect();
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "poler-mesh: неизвестный инструмент «{name}». Доступно {}: {}",
                            known.len(),
                            known.join(", ")
                        )
                    }],
                    "isError": true
                }))
            }
        }
    }

    /// Имена всех инструментов (для диагностики).
    pub fn tool_names(&self) -> Vec<String> {
        self.route.keys().cloned().collect()
    }

    /// Строка диагностики: узлы + счётчики.
    pub fn status_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (i, n) in self.nodes.iter().enumerate() {
            let count = self.route.values().filter(|&&v| v == i).count();
            out.push(format!(
                "  {:<12} {:<16} инструментов: {}",
                n.id, n.server_name, count
            ));
        }
        out.push(format!("  всего инструментов: {}", self.tools.len()));
        if !self.conflicts.is_empty() {
            out.push(format!("  конфликтов имён: {}", self.conflicts.len()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_hub() -> Hub {
        Hub {
            nodes: Vec::new(),
            tools: Vec::new(),
            route: HashMap::new(),
            conflicts: Vec::new(),
        }
    }

    #[test]
    fn dispatch_initialize_reports_mesh() {
        let mut hub = empty_hub();
        let resp = hub
            .dispatch(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}))
            .unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "poler-mesh");
        assert_eq!(resp["result"]["protocolVersion"], crate::PROTOCOL_VERSION);
    }

    #[test]
    fn dispatch_ping_returns_empty_object() {
        let mut hub = empty_hub();
        let resp = hub
            .dispatch(&json!({"jsonrpc":"2.0","id":2,"method":"ping"}))
            .unwrap();
        assert!(resp["result"].is_object());
    }

    #[test]
    fn dispatch_unknown_tool_is_error_result() {
        let mut hub = empty_hub();
        let resp = hub
            .dispatch(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"nope","arguments":{}}}))
            .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("неизвестный инструмент"));
    }

    #[test]
    fn dispatch_unknown_method_is_jsonrpc_error() {
        let mut hub = empty_hub();
        let resp = hub
            .dispatch(&json!({"jsonrpc":"2.0","id":4,"method":"resources/list"}))
            .unwrap();
        assert_eq!(resp["error"]["code"], -32603);
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("не поддерживается"));
    }

    #[test]
    fn notification_gets_no_response() {
        let mut hub = empty_hub();
        assert!(hub
            .dispatch(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .is_none());
    }

    #[test]
    fn build_rejects_empty() {
        assert!(Hub::build(&[]).is_err());
    }

    #[test]
    fn status_lines_counts_tools_per_node() {
        let mut hub = empty_hub();
        hub.route.insert("a".into(), 0);
        hub.route.insert("b".into(), 0);
        hub.route.insert("c".into(), 1);
        hub.tools = vec![json!({"name":"a"}), json!({"name":"b"}), json!({"name":"c"})];
        // nodes пуст — status_lines не должен паниковать
        let lines = hub.status_lines();
        assert!(lines.last().unwrap().contains("всего инструментов: 3"));
    }
}
