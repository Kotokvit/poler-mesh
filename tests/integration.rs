//! Integration-тесты poler-mesh: сетка поднимается целиком на мок-узлах.
//! Никакой сети, никаких внешних бинарников — только сам poler-mesh
//! (через CARGO_BIN_EXE) в двух ролях: хаб и мок-узлы.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

struct HubProc {
    child: Child,
    reader: BufReader<ChildStdout>,
}

impl HubProc {
    fn send(&mut self, v: &Value) {
        let line = serde_json::to_string(v).unwrap();
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin.write_all(line.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line).unwrap();
            assert!(n > 0, "хаб закрыл stdout");
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            return serde_json::from_str(t).unwrap_or_else(|e| panic!("не JSON «{t}»: {e}"));
        }
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        loop {
            let r = self.recv();
            if r.get("id").and_then(|i| i.as_u64()) == Some(id) {
                return r;
            }
        }
    }
}

impl Drop for HubProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn mesh_config(dir: &std::path::Path, nodes: &[(&str, &str)]) -> PathBuf {
    let mut toml = String::new();
    for (id, suffix) in nodes {
        toml.push_str(&format!(
            "[[node]]\nid = \"{id}\"\ncmd = \"{exe}\"\nargs = [\"--mock-node\", \"{suffix}\"]\n\n",
            exe = env!("CARGO_BIN_EXE_poler-mesh"),
        ));
    }
    let p = dir.join("mesh.toml");
    std::fs::write(&p, toml).unwrap();
    p
}

fn spawn_hub(cfg: &std::path::Path) -> HubProc {
    let mut child = Command::new(env!("CARGO_BIN_EXE_poler-mesh"))
        .arg("--mcp-stdio")
        .arg("--config")
        .arg(cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn poler-mesh");
    let reader = BufReader::new(child.stdout.take().expect("stdout у хаба"));
    HubProc { child, reader }
}

#[test]
fn hub_aggregates_two_mock_nodes_and_routes_calls() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = mesh_config(tmp.path(), &[("a", "alpha"), ("b", "beta")]);
    let mut hub = spawn_hub(&cfg);

    // initialize
    let init = hub.request(1, "initialize", json!({}));
    assert_eq!(init["result"]["serverInfo"]["name"], "poler-mesh");

    // tools/list: 4 инструмента из двух узлов
    let list = hub.request(2, "tools/list", json!({}));
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4, "2 узла × 2 инструмента");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in ["alpha_echo", "alpha_ping", "beta_echo", "beta_ping"] {
        assert!(names.contains(&expected), "нет {expected}: {names:?}");
    }
    // каждый инструмент помечен происхождением
    let alpha = tools.iter().find(|t| t["name"] == "alpha_echo").unwrap();
    assert_eq!(alpha["_mesh_node"]["id"], "a");

    // маршрутизация: вызов уходит в правильный узел
    let echo = hub.request(
        3,
        "tools/call",
        json!({"name":"beta_echo","arguments":{"text":"привет сетка"}}),
    );
    let text = echo["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(text, "[beta] привет сетка");

    let ping = hub.request(4, "tools/call", json!({"name":"alpha_ping","arguments":{}}));
    assert_eq!(ping["result"]["content"][0]["text"], "pong от alpha");

    // неизвестный инструмент — честный isError
    let unknown = hub.request(5, "tools/call", json!({"name":"nope","arguments":{}}));
    assert_eq!(unknown["result"]["isError"], true);

    // ping
    let pong = hub.request(6, "ping", json!({}));
    assert!(pong["result"].is_object());
}

#[test]
fn notification_gets_no_response_line() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = mesh_config(tmp.path(), &[("only", "solo")]);
    let mut hub = spawn_hub(&cfg);

    hub.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    // на уведомление хаб молчит; следующий запрос отвечает быстро
    let pong = hub.request(10, "ping", json!({}));
    assert!(pong["result"].is_object());
}

#[test]
fn nodes_command_prints_diagnostics() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = mesh_config(tmp.path(), &[("a", "alpha"), ("b", "beta")]);
    let out = Command::new(env!("CARGO_BIN_EXE_poler-mesh"))
        .arg("--nodes")
        .arg("--config")
        .arg(&cfg)
        .output()
        .expect("run poler-mesh nodes");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("alpha_echo"), "{stdout}");
    assert!(stdout.contains("beta_ping"), "{stdout}");
    assert!(stdout.contains("всего инструментов: 4"), "{stdout}");
}

#[test]
fn bad_node_cmd_is_clear_error() {
    let tmp = tempfile::tempdir().unwrap();
    let toml = "[[node]]\nid = \"broken\"\ncmd = \"definitely-not-a-real-binary\"\nargs = []\n";
    let cfg = tmp.path().join("mesh.toml");
    std::fs::write(&cfg, toml).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_poler-mesh"))
        .arg("--mcp-stdio")
        .arg("--config")
        .arg(&cfg)
        .output()
        .expect("run poler-mesh");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("broken"), "{stderr}");
    assert!(stderr.contains("не удалось запустить"), "{stderr}");
}

#[test]
fn http_serves_mesh_with_one_token() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = mesh_config(tmp.path(), &[("a", "alpha"), ("b", "beta")]);

    let mut child = Command::new(env!("CARGO_BIN_EXE_poler-mesh"))
        .arg("--mcp-http")
        .arg("127.0.0.1:0")
        .arg("--mcp-token")
        .arg("test-token-123")
        .arg("--config")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn poler-mesh http");

    // ждём строку POLER_MESH_HTTP_BIND: 127.0.0.1:PORT из stderr
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let mut bind_addr = String::new();
    for _ in 0..50 {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "poler-mesh http умер до печати bind");
        if let Some(rest) = line.trim().strip_prefix("POLER_MESH_HTTP_BIND: ") {
            bind_addr = rest.to_string();
            break;
        }
    }
    assert!(!bind_addr.is_empty(), "не нашли POLER_MESH_HTTP_BIND в stderr");

    // health без токена
    let health = http_get(&bind_addr, "/health");
    assert!(health.0 == 200, "health: {}", health.0);
    assert!(health.1.contains("poler-mesh"), "{}", health.1);

    // tools/list с токеном
    let body = serde_json::to_string(&json!({
        "jsonrpc":"2.0","id":1,"method":"tools/list","params":{}
    }))
    .unwrap();
    let resp = http_post(&bind_addr, "/mcp", "test-token-123", &body);
    assert_eq!(resp.0, 200, "{}", resp.2);
    let v: Value = serde_json::from_str(&resp.1).unwrap();
    assert_eq!(v["result"]["tools"].as_array().unwrap().len(), 4);

    // tools/call через HTTP
    let body = serde_json::to_string(&json!({
        "jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"alpha_echo","arguments":{"text":"через http"}}
    }))
    .unwrap();
    let resp = http_post(&bind_addr, "/mcp", "test-token-123", &body);
    let v: Value = serde_json::from_str(&resp.1).unwrap();
    assert_eq!(v["result"]["content"][0]["text"], "[alpha] через http");

    // без токена — 401
    let resp = http_post(&bind_addr, "/mcp", "wrong", &body);
    assert_eq!(resp.0, 401);

    let _ = child.kill();
    let _ = child.wait();
}

/// Мини HTTP-клиент на std::net (без зависимостей).
fn http_get(addr: &str, path: &str) -> (u16, String) {
    use std::net::TcpStream;
    let mut s = TcpStream::connect(addr).unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn http_post(addr: &str, path: &str, token: &str, body: &str) -> (u16, String, String) {
    use std::net::TcpStream;
    let mut s = TcpStream::connect(addr).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body, text)
}
