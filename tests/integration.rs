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

// ===========================================================================
// poler-wire v0.2.0: poler-relay + poler-mesh --mcp-link (docs/wire.md)
// ===========================================================================

use poler_mesh::keys::{
    envelope_canonical, open_envelope_ephemeral, seal_envelope, Identity, SealedEnvelope,
};
use poler_mesh::relay::{
    token_sha256, AgentReg, ClientReg, KeysSection, RelayCfg, RelaySection, TokenReg,
};

struct RelayProc {
    child: Child,
    bind: String,
    http: String,
    client_identity: Identity,
    agent_identity: Identity,
    relay_verify_b64: String,
    token: String,
}

fn relay_exe() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_poler_relay") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_BIN_EXE_poler-mesh")).with_file_name("poler-relay")
}

fn spawn_relay(tmp: &std::path::Path) -> RelayProc {
    let client_identity = Identity::generate();
    let agent_identity = Identity::generate();
    let relay_identity = Identity::generate();
    let token = "poler_mesh_it_token";

    let cfg = RelayCfg {
        relay: RelaySection {
            id: "it-relay".into(),
            bind: "127.0.0.1:0".into(),
            http: "127.0.0.1:0".into(),
            exec_timeout_ms: 5000,
        },
        keys: KeysSection {
            identity_seed: poler_mesh::keys::b64_encode(relay_identity.signing.as_bytes()),
        },
        clients: vec![ClientReg {
            id: "main".into(),
            verify_key: client_identity.verify_key_b64(),
            box_key: client_identity.box_public_b64(),
        }],
        agents: vec![AgentReg {
            id: "glm".into(),
            verify_key: agent_identity.verify_key_b64(),
            client: "main".into(),
        }],
        tokens: vec![TokenReg {
            hash: token_sha256(token),
            client: "main".into(),
        }],
    };
    let cfg_path = tmp.join("relay.toml");
    std::fs::write(&cfg_path, toml::to_string(&cfg).unwrap()).unwrap();
    let log_path = tmp.join("relay.log");

    let mut child = Command::new(relay_exe())
        .arg("--config")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&log_path).unwrap()))
        .spawn()
        .expect("spawn poler-relay");

    // ждём PORы в relay.log (bind/http с :0)
    let mut bind = String::new();
    let mut http = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        for line in log.lines() {
            if let Some(rest) = line.trim().strip_prefix("POLER_RELAY_BIND=") {
                bind = rest.to_string();
            }
            if let Some(rest) = line.trim().strip_prefix("POLER_RELAY_HTTP=") {
                http = rest.to_string();
            }
        }
        if !bind.is_empty() && !http.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        !bind.is_empty() && !http.is_empty(),
        "relay не напечатал порты; лог:\n{}",
        std::fs::read_to_string(&log_path).unwrap_or_default()
    );

    RelayProc {
        child,
        bind,
        http,
        client_identity,
        agent_identity,
        relay_verify_b64: relay_identity.verify_key_b64(),
        token: token.to_string(),
    }
}

impl Drop for RelayProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Убивает дочерний процесс даже при панике теста (утёкшие link-клиенты
/// с бесконечным реконнектом отравляют следующие прогоны).
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_link(relay: &RelayProc, tmp: &std::path::Path, mesh_cfg: &std::path::Path) -> Child {
    let identity_path = tmp.join("link-identity.json");
    std::fs::write(&identity_path, relay.client_identity.to_json()).unwrap();
    Command::new(env!("CARGO_BIN_EXE_poler-mesh"))
        .arg("--mcp-link")
        .arg(&relay.bind)
        .arg("--link-identity")
        .arg(&identity_path)
        .arg("--relay-key")
        .arg(&relay.relay_verify_b64)
        .arg("--agent")
        .arg(format!("glm={}", relay.agent_identity.verify_key_b64()))
        .arg("--config")
        .arg(mesh_cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn poler-mesh --mcp-link")
}

/// Ждать, пока /health не покажет клиента online.
fn wait_link_up(http: &str) {
    for _ in 0..100 {
        let h = http_get(http, "/health");
        if h.0 == 200 && h.1.contains("\"main\"") {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("link-клиент не подключился к релею за 10 c");
}

fn mcp(method: &str, params: Value, id: u64) -> String {
    serde_json::to_string(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap()
}

#[test]
fn relay_health_and_plain_mode_full_loop() {
    let tmp = tempfile::tempdir().unwrap();
    let relay = spawn_relay(tmp.path());
    let mesh_cfg = mesh_config(tmp.path(), &[("a", "alpha")]);

    // до подключения клиента: health ок, но clients_online пуст и POST → 502
    let h = http_get(&relay.http, "/health");
    assert_eq!(h.0, 200);
    let hv: Value = serde_json::from_str(&h.1).unwrap();
    assert_eq!(hv["relay"], "it-relay");
    assert_eq!(hv["clients_online"].as_array().unwrap().len(), 0);

    let resp = http_post(&relay.http, "/mcp", &relay.token, &mcp("ping", json!({}), 1));
    assert_eq!(resp.0, 502, "клиент офлайн — ждём 502: {}", resp.1);

    // подключаем link-клиента (мок-узел внутри)
    let link = KillOnDrop(spawn_link(&relay, tmp.path(), &mesh_cfg));
    wait_link_up(&relay.http);

    // initialize через всю цепочку: агент → HTTP → relay → TCP → mesh → hub
    let resp = http_post(&relay.http, "/mcp", &relay.token, &mcp("initialize", json!({}), 1));
    assert_eq!(resp.0, 200, "{}", resp.1);
    let v: Value = serde_json::from_str(&resp.1).unwrap();
    assert_eq!(v["result"]["serverInfo"]["name"], "poler-mesh");

    // tools/list мок-узла виден снаружи
    let resp = http_post(&relay.http, "/mcp", &relay.token, &mcp("tools/list", json!({}), 2));
    let v: Value = serde_json::from_str(&resp.1).unwrap();
    let tools = v["result"]["tools"].as_array().unwrap();
    assert!(tools.len() >= 2);
    assert!(tools.iter().any(|t| t["name"] == "alpha_echo"));

    // tools/call через всю сетку
    let body = mcp(
        "tools/call",
        json!({"name":"alpha_echo","arguments":{"text":"без туннелей"}}),
        3,
    );
    let resp = http_post(&relay.http, "/mcp", &relay.token, &body);
    assert_eq!(resp.0, 200);
    let v: Value = serde_json::from_str(&resp.1).unwrap();
    assert_eq!(v["result"]["content"][0]["text"], "[alpha] без туннелей");

    // без токена — 401; мусорный JSON — 400; левый путь — 404
    assert_eq!(http_post(&relay.http, "/mcp", "wrong", &body).0, 401);
    assert_eq!(
        http_post(&relay.http, "/mcp", &relay.token, "not json").0,
        400
    );
    assert_eq!(http_post(&relay.http, "/nope", &relay.token, "{}").0, 404);
}

#[test]
fn relay_sealed_mode_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let relay = spawn_relay(tmp.path());
    let mesh_cfg = mesh_config(tmp.path(), &[("a", "alpha")]);
    let link = KillOnDrop(spawn_link(&relay, tmp.path(), &mesh_cfg));
    wait_link_up(&relay.http);

    // агент запечатывает tools/call для клиента (E2E, релей видит только b64)
    let mcp_req = mcp(
        "tools/call",
        json!({"name":"alpha_echo","arguments":{"text":"e2e secret"}}),
        7,
    );
    let (env, agent_eph) = seal_envelope(
        "glm",
        &relay.client_identity.box_public_b64(),
        4242,
        111,
        &mcp_req,
        &relay.agent_identity.signing,
    )
    .unwrap();
    let env_str = serde_json::to_string(&env).unwrap();

    let resp = http_post(&relay.http, "/mcp-sealed", "x", &env_str);
    assert_eq!(resp.0, 200, "{}", resp.1);

    // ответ — конверт, запечатанный НА ЭФЕМЕРНЫЙ ключ агента
    let resp_env: SealedEnvelope = serde_json::from_str(&resp.1).unwrap();
    assert_eq!(resp_env.from, "main");
    let opened = open_envelope_ephemeral(
        &resp_env,
        &agent_eph,
        &relay.client_identity.signing.verifying_key(),
    )
    .unwrap();
    let v: Value = serde_json::from_str(&opened).unwrap();
    assert_eq!(v["result"]["content"][0]["text"], "[alpha] e2e secret");
}

#[test]
fn relay_sealed_rejects_tampering_and_replay() {
    let tmp = tempfile::tempdir().unwrap();
    let relay = spawn_relay(tmp.path());
    let mesh_cfg = mesh_config(tmp.path(), &[("a", "alpha")]);
    let link = KillOnDrop(spawn_link(&relay, tmp.path(), &mesh_cfg));
    wait_link_up(&relay.http);

    let mcp_req = mcp("ping", json!({}), 1);

    // 1. подделанный шифротекст → подпись недействительна → 401
    let (mut env, _) = seal_envelope(
        "glm",
        &relay.client_identity.box_public_b64(),
        10,
        20,
        &mcp_req,
        &relay.agent_identity.signing,
    )
    .unwrap();
    let ct = poler_mesh::keys::b64_decode(&env.ct).unwrap();
    let mut bad_ct = ct.clone();
    bad_ct[0] ^= 0xFF;
    env.ct = poler_mesh::keys::b64_encode(&bad_ct);
    let resp = http_post(&relay.http, "/mcp-sealed", "x", &serde_json::to_string(&env).unwrap());
    assert_eq!(resp.0, 401);

    // 2. незарегистрированный агент → 401
    let stranger = Identity::generate();
    let (env2, _) = seal_envelope(
        "unknown-agent",
        &relay.client_identity.box_public_b64(),
        11,
        21,
        &mcp_req,
        &stranger.signing,
    )
    .unwrap();
    let resp = http_post(&relay.http, "/mcp-sealed", "x", &serde_json::to_string(&env2).unwrap());
    assert_eq!(resp.0, 401);

    // 3. нормальный конверт проходит…
    let (env3, _) = seal_envelope(
        "glm",
        &relay.client_identity.box_public_b64(),
        12,
        22,
        &mcp_req,
        &relay.agent_identity.signing,
    )
    .unwrap();
    let resp = http_post(&relay.http, "/mcp-sealed", "x", &serde_json::to_string(&env3).unwrap());
    assert_eq!(resp.0, 200);

    // 4. …но НОВЫЙ cmd_id со СТАРЫМ nonce — replay → 401
    let mut env4 = env3.clone();
    env4.cmd_id = "13".to_string();
    env4.sig = relay.agent_identity.sign_b64(&envelope_canonical(&env4));
    let resp = http_post(&relay.http, "/mcp-sealed", "x", &serde_json::to_string(&env4).unwrap());
    assert_eq!(resp.0, 401);
}

#[test]
fn relay_sealed_idempotency_same_cmd_id_new_nonce() {
    let tmp = tempfile::tempdir().unwrap();
    let relay = spawn_relay(tmp.path());
    let mesh_cfg = mesh_config(tmp.path(), &[("a", "alpha")]);
    let link = KillOnDrop(spawn_link(&relay, tmp.path(), &mesh_cfg));
    wait_link_up(&relay.http);

    // ретрай-контракт (wire.md §6): тот же cmd_id, НОВЫЙ nonce и подпись
    let call = mcp(
        "tools/call",
        json!({"name":"alpha_echo","arguments":{"text":"idem"}}),
        1,
    );
    let (env1, agent_eph) = seal_envelope(
        "glm",
        &relay.client_identity.box_public_b64(),
        555,
        1001,
        &call,
        &relay.agent_identity.signing,
    )
    .unwrap();
    let r1 = http_post(&relay.http, "/mcp-sealed", "x", &serde_json::to_string(&env1).unwrap());
    assert_eq!(r1.0, 200);

    let mut env2 = env1.clone();
    env2.nonce = "1002".to_string();
    env2.sig = relay.agent_identity.sign_b64(&envelope_canonical(&env2));
    let r2 = http_post(&relay.http, "/mcp-sealed", "x", &serde_json::to_string(&env2).unwrap());
    assert_eq!(r2.0, 200);

    // оба ответа одинаковы (клиент отдал кэш, не исполняя повторно)
    let open = |body: &str| -> String {
        let e: SealedEnvelope = serde_json::from_str(body).unwrap();
        open_envelope_ephemeral(
            &e,
            &agent_eph,
            &relay.client_identity.signing.verifying_key(),
        )
        .unwrap()
    };
    let v1: Value = serde_json::from_str(&open(&r1.1)).unwrap();
    let v2: Value = serde_json::from_str(&open(&r2.1)).unwrap();
    assert_eq!(v1["result"]["content"][0]["text"], "[alpha] idem");
    assert_eq!(
        v1["result"]["content"][0]["text"],
        v2["result"]["content"][0]["text"]
    );
}

#[test]
fn link_client_reconnects_after_death() {
    let tmp = tempfile::tempdir().unwrap();
    let relay = spawn_relay(tmp.path());
    let mesh_cfg = mesh_config(tmp.path(), &[("a", "alpha")]);

    let mut link = KillOnDrop(spawn_link(&relay, tmp.path(), &mesh_cfg));
    wait_link_up(&relay.http);
    let body = mcp("ping", json!({}), 1);
    let resp = http_post(&relay.http, "/mcp", &relay.token, &body);
    assert_eq!(resp.0, 200);

    // рвём линк: клиент умирает → релей это замечает → 502
    let _ = link.0.kill();
    let _ = link.0.wait();
    let mut got_502 = false;
    for _ in 0..50 {
        let r = http_post(&relay.http, "/mcp", &relay.token, &body);
        if r.0 == 502 {
            got_502 = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(got_502, "релей не заметил смерть линк-клиента");

    // перезапуск клиента: та же идентичность → тот же client_id → всё снова работает
    let link2 = KillOnDrop(spawn_link(&relay, tmp.path(), &mesh_cfg));
    wait_link_up(&relay.http);
    let resp = http_post(&relay.http, "/mcp", &relay.token, &body);
    assert_eq!(resp.0, 200);
}
