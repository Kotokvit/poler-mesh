//! # poler-relay — слепой маршрутизатор POLER Mesh (docs/wire.md)
//!
//! Две ноги:
//! * **client-leg** (`bind`, голый TCP): `poler-mesh --mcp-link` подключается
//!   исходяще, handshake Ed25519+X25519, дальше AEAD-кадры;
//! * **HTTP-фасад** (`http`): агенты → `POST /mcp` (Bearer, plain) или
//!   `POST /mcp-sealed` (конверт, релей видит только шифротекст).
//!
//! Релей НЕ хранит секретов для расшифровки: sealed-режим проходит сквозь
//! (подпись агента проверяется над шифротекстом, расшифровывает только клиент).
//!
//! Транспорт: std::net + треды, ручной HTTP/1.1 — как в v0.1.0, ноль async.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::keys::{
    b64_32, envelope_canonical, verify_sig, SealedEnvelope,
};
use crate::wire::{
    self, ephemeral, hello_ack_canonical, hello_canonical, time_in_window, x25519_pub,
    x25519_pub_b64, Frame, Hello, HelloAck, ReplayGuard, Session, FT_ERROR, FT_EXEC,
    FT_HELLO, FT_HELLO_ACK, FT_PING, FT_PONG, FT_RESULT, WIRE_VERSION,
};

const HTTP_MAX_CONNS: usize = 32;
const HTTP_HEADER_CAP: usize = 16 * 1024;
const HTTP_BODY_CAP: usize = 8 * 1024 * 1024;
const HTTP_IDLE: Duration = Duration::from_secs(65);
/// Простой на client-leg до разрыва (клиент пингует каждые 25 c).
const LINK_IDLE: Duration = Duration::from_secs(90);
/// Период пинга релея в сторону клиента (держит NAT и detects мёртвые линки).
const LINK_PING_EVERY: Duration = Duration::from_secs(25);
const LINK_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Конфиг
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub struct RelaySection {
    pub id: String,
    pub bind: String,
    pub http: String,
    #[serde(default = "d_exec_timeout")]
    pub exec_timeout_ms: u64,
}

fn d_exec_timeout() -> u64 {
    120_000
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeysSection {
    /// b64 Ed25519 seed идентичности релея.
    pub identity_seed: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientReg {
    pub id: String,
    /// b64 Ed25519 verify-key клиента.
    pub verify_key: String,
    /// b64 X25519 static pub клиента (для документации; релей не использует).
    pub box_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentReg {
    pub id: String,
    /// b64 Ed25519 verify-key агента — проверка подписи над шифротекстом.
    pub verify_key: String,
    /// К какому клиенту маршрутизировать.
    pub client: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenReg {
    /// sha256-hex Bearer-токена (сам токен в конфиге не хранится).
    pub hash: String,
    pub client: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RelayCfg {
    pub relay: RelaySection,
    pub keys: KeysSection,
    #[serde(default)]
    pub clients: Vec<ClientReg>,
    #[serde(default)]
    pub agents: Vec<AgentReg>,
    #[serde(default)]
    pub tokens: Vec<TokenReg>,
}

impl RelayCfg {
    pub fn parse(text: &str) -> Result<RelayCfg, String> {
        toml::from_str(text).map_err(|e| format!("relay.toml: {e}"))
    }

    pub fn find_client(&self, id: &str) -> Option<&ClientReg> {
        self.clients.iter().find(|c| c.id == id)
    }

    pub fn find_agent(&self, id: &str) -> Option<&AgentReg> {
        self.agents.iter().find(|a| a.id == id)
    }

    /// Проверить Bearer-токен → целевой клиент.
    pub fn token_client(&self, token: &str) -> Option<String> {
        let h = token_sha256(token);
        self.tokens
            .iter()
            .find(|t| t.hash.eq_ignore_ascii_case(&h))
            .map(|t| t.client.clone())
    }
}

/// sha256-hex для хранения хэша токена.
pub fn token_sha256(token: &str) -> String {
    let d = Sha256::digest(token.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Пример конфига для `--init` (идентичность и токен генерируются).
pub fn example_toml(relay_id: &str, identity_seed_b64: &str, token_hash: &str) -> String {
    format!(
        r#"# poler-relay — конфиг (docs/wire.md). Права на файл: 600.
[relay]
id = "{relay_id}"
# client-leg: сюда ИСХОДЯЩЕ подключается poler-mesh --mcp-link
bind = "0.0.0.0:8771"
# HTTP-фасад для агентов (POST /mcp, POST /mcp-sealed, GET /health)
http = "0.0.0.0:8770"
exec_timeout_ms = 120000

[keys]
identity_seed = "{identity_seed_b64}"

# Зарегистрированные link-клиенты (вывод `poler-mesh --init-link`):
[[clients]]
id = "main"
verify_key = "<b64 Ed25519 pub клиента>"
box_key = "<b64 X25519 pub клиента>"

# Агенты с криптоспособностями (sealed-режим; вывод poler_agent.py --init):
[[agents]]
id = "glm"
verify_key = "<b64 Ed25519 pub агента>"
client = "main"

# Bearer-токены для plain-режима (хранится ТОЛЬКО sha256-hex):
[[tokens]]
hash = "{token_hash}"
client = "main"
"#
    )
}

// ---------------------------------------------------------------------------
// Состояние
// ---------------------------------------------------------------------------

enum Outcome {
    Ok(String),
    Err(String),
}

struct Link {
    /// Канал записи кадров в TCP клиента.
    tx: Sender<Vec<u8>>,
    /// AEAD-сессия (send-половина нужна http-тредам).
    session: Arc<Session>,
    /// Уникальный id соединения: уборка удаляет только СВОЙ линк.
    conn_id: u64,
}

struct RelayState {
    cfg: RelayCfg,
    signing: SigningKey,
    links: Mutex<HashMap<String, Link>>,
    /// cmd_id → (ждун HTTP, владелец-клиент).
    pending: Mutex<HashMap<u64, (Sender<Outcome>, String)>>,
    /// Анти-replay по агентам.
    agent_replay: Mutex<HashMap<String, ReplayGuard>>,
}

impl RelayState {
    fn link_of(&self, client_id: &str) -> Option<(Sender<Vec<u8>>, Arc<Session>)> {
        let links = self.links.lock().ok()?;
        let l = links.get(client_id)?;
        Some((l.tx.clone(), Arc::clone(&l.session)))
    }

    fn fail_pending_of(&self, client_id: &str, reason: &str) {
        if let Ok(mut p) = self.pending.lock() {
            let keys: Vec<u64> = p
                .iter()
                .filter(|(_, (_, owner))| owner == client_id)
                .map(|(k, _)| *k)
                .collect();
            for k in keys {
                if let Some((tx, _)) = p.remove(&k) {
                    let _ = tx.send(Outcome::Err(reason.to_string()));
                }
            }
        }
    }

    /// Replay-проверка агента (создаёт фильтр при первом обращении).
    fn agent_check(&self, agent_id: &str, time: u64, nonce: u64) -> Result<(), String> {
        let mut guards = self
            .agent_replay
            .lock()
            .map_err(|_| "внутреннее состояние".to_string())?;
        guards
            .entry(agent_id.to_string())
            .or_insert_with(ReplayGuard::new)
            .check(time, nonce)
    }
}

// ---------------------------------------------------------------------------
// Запуск
// ---------------------------------------------------------------------------

/// Поднять релей. Блокируется навсегда (два слушателя в тредах).
pub fn run(cfg: RelayCfg) -> Result<(), String> {
    let signing = SigningKey::from_bytes(&b64_32(&cfg.keys.identity_seed)?);
    let state = Arc::new(RelayState {
        cfg,
        signing,
        links: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
        agent_replay: Mutex::new(HashMap::new()),
    });

    // --- client-leg ---
    let bind = state.cfg.relay.bind.clone();
    let listener = TcpListener::bind(&bind).map_err(|e| format!("bind {bind}: {e}"))?;
    let actual = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.clone());
    eprintln!("poler-relay: client-leg слушаю tcp://{actual}");
    eprintln!("POLER_RELAY_BIND={actual}");

    let st = Arc::clone(&state);
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let st = Arc::clone(&st);
            thread::spawn(move || handle_link_conn(stream, st));
        }
    });

    // --- HTTP-фасад ---
    let http_bind = state.cfg.relay.http.clone();
    let http_listener =
        TcpListener::bind(&http_bind).map_err(|e| format!("bind {http_bind}: {e}"))?;
    let http_actual = http_listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| http_bind.clone());
    eprintln!(
        "poler-relay {}: HTTP-фасад http://{}  (POST /mcp | POST /mcp-sealed | GET /health)",
        state.cfg.relay.id, http_actual
    );
    eprintln!("POLER_RELAY_HTTP={http_actual}");

    let active = Arc::new(AtomicUsize::new(0));
    for conn in http_listener.incoming() {
        let Ok(stream) = conn else { continue };
        if active.load(Ordering::Relaxed) >= HTTP_MAX_CONNS {
            let mut w = stream;
            let _ = write_http(&mut w, 503, "text/plain", b"too many connections", false);
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let st = Arc::clone(&state);
        let active = Arc::clone(&active);
        thread::spawn(move || {
            handle_http_conn(stream, &st);
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// client-leg
// ---------------------------------------------------------------------------

fn handle_link_conn(stream: TcpStream, state: Arc<RelayState>) {
    let _ = stream.set_nodelay(true);
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let mut reader = match stream.try_clone() {
        Ok(r) => r,
        Err(_) => return,
    };
    let _ = reader.set_read_timeout(Some(LINK_IDLE));

    // 1. HELLO
    let hello = match read_hello(&mut reader) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("poler-relay: {peer}: handshake: {e}");
            return;
        }
    };
    let reg = match state.cfg.find_client(&hello.client_id) {
        Some(r) => r.clone(),
        None => {
            eprintln!(
                "poler-relay: {peer}: клиент «{}» не зарегистрирован",
                hello.client_id
            );
            return;
        }
    };
    let client_vk = match crate::keys::verify_key_from_b64(&reg.verify_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("poler-relay: конфиг клиента «{}»: {e}", reg.id);
            return;
        }
    };
    if !time_in_window(hello.time) {
        eprintln!("poler-relay: {peer}: HELLO вне окна времени");
        return;
    }
    if let Err(e) = verify_sig(&client_vk, &hello_canonical(&hello), &hello.sig) {
        eprintln!("poler-relay: {peer}: подпись HELLO: {e}");
        return;
    }

    // 2. HELLO_ACK + сессия
    let (eph_secret, eph_pub) = ephemeral();
    let client_eph = match x25519_pub(&hello.eph) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("poler-relay: {peer}: eph: {e}");
            return;
        }
    };
    let shared = *eph_secret.diffie_hellman(&client_eph).as_bytes();
    let ack = HelloAck {
        v: WIRE_VERSION,
        relay_id: state.cfg.relay.id.clone(),
        eph: x25519_pub_b64(&eph_pub),
        sig: String::new(),
    };
    let ack = {
        let canonical = hello_ack_canonical(&ack, &hello.eph);
        let sig = state.signing.sign(canonical.as_bytes());
        HelloAck {
            sig: crate::keys::b64_encode(&sig.to_bytes()),
            ..ack
        }
    };
    let (c2r, r2c) = match wire::derive_session(
        &shared,
        client_eph.as_bytes(),
        eph_pub.as_bytes(),
    ) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("poler-relay: {peer}: derive: {e}");
            return;
        }
    };
    let session = Arc::new(Session::relay_side(c2r, r2c));
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let _ = writer.set_write_timeout(Some(LINK_WRITE_TIMEOUT));
    let ack_frame = wire::encode_plain_frame(&Frame::plain(
        FT_HELLO_ACK,
        serde_json::to_vec(&ack).unwrap_or_default().as_slice(),
    ));
    if writer.write_all(&ack_frame).is_err() {
        return;
    }

    // 3. writer-тред + регистрация линка
    let conn_id = wire::os_random_u64();
    let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
    {
        let mut links = match state.links.lock() {
            Ok(l) => l,
            Err(_) => return,
        };
        if let Some(old) = links.insert(
            hello.client_id.clone(),
            Link {
                tx: tx.clone(),
                session: Arc::clone(&session),
                conn_id,
            },
        ) {
            // старый линк того же клиента — гасим его writer
            let _ = old.tx.send(Vec::new()); // пустой кадр = poison pill
        }
    }
    eprintln!("poler-relay: клиент «{}» на связи ({peer})", hello.client_id);

    let writer_client = hello.client_id.clone();
    let w_state = Arc::clone(&state);
    thread::spawn(move || writer_loop(writer, rx, w_state, writer_client));

    // пингер: держит NAT живым и детектит мёртвые соединения
    let pinger_tx = tx.clone();
    let pinger_session = Arc::clone(&session);
    thread::spawn(move || loop {
        thread::sleep(LINK_PING_EVERY);
        let frame = pinger_session.seal(FT_PING, 0, wire::new_nonce(), b"{\"t\":0}");
        if pinger_tx.send(frame).is_err() {
            return;
        }
    });

    // 4. reader-цикл
    loop {
        let raw = match wire::read_raw_frame(&mut reader) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("poler-relay: клиент «{}»: чтение: {e}", hello.client_id);
                break;
            }
        };
        let frame = match session.open(&raw) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("poler-relay: клиент «{}»: кадр: {e}", hello.client_id);
                break;
            }
        };
        match frame.ft {
            FT_PING => {
                let pong = session.seal(FT_PONG, frame.cmd_id, frame.nonce, frame.payload.as_slice());
                if tx.send(pong).is_err() {
                    break;
                }
            }
            FT_RESULT => {
                if let Err(e) = resolve_result(&state, &frame) {
                    eprintln!("poler-relay: RESULT: {e}");
                }
            }
            FT_EXEC | FT_HELLO | FT_HELLO_ACK | FT_ERROR | FT_PONG => {
                eprintln!(
                    "poler-relay: клиент «{}»: неожиданный тип кадра 0x{:02x}",
                    hello.client_id, frame.ft
                );
            }
            _ => {}
        }
    }

    // 5. уборка
    drop_link(&state, &hello.client_id, conn_id, tx);
    eprintln!("poler-relay: клиент «{}» отключился", hello.client_id);
}

fn drop_link(state: &RelayState, client_id: &str, conn_id: u64, tx: Sender<Vec<u8>>) {
    let _ = tx.send(Vec::new()); // погасить writer/pinger
    if let Ok(mut links) = state.links.lock() {
        // удаляем только если это всё ещё НАШ линк (не заменённый новым)
        if let Some(cur) = links.get(client_id) {
            if cur.conn_id == conn_id {
                links.remove(client_id);
            }
        }
    }
    state.fail_pending_of(client_id, "link-клиент отключён");
}

fn writer_loop(
    mut writer: TcpStream,
    rx: Receiver<Vec<u8>>,
    state: Arc<RelayState>,
    client_id: String,
) {
    while let Ok(bytes) = rx.recv() {
        if bytes.is_empty() {
            return; // poison pill
        }
        if writer.write_all(&bytes).is_err() {
            break;
        }
    }
    state.fail_pending_of(&client_id, "запись в TCP не удалась");
}

fn read_hello(reader: &mut TcpStream) -> Result<Hello, String> {
    let raw = wire::read_raw_frame(reader)?;
    let (ft, _, _, _, _) = wire::parse_header(&raw)?;
    if ft != FT_HELLO {
        return Err(format!("ожидался HELLO (0x01), пришёл 0x{ft:02x}"));
    }
    let payload = &raw[33..];
    serde_json::from_slice(payload).map_err(|e| format!("HELLO json: {e}"))
}

/// RESULT-кадр → разбудить ждуна HTTP.
fn resolve_result(state: &RelayState, frame: &Frame) -> Result<(), String> {
    let v: Value = serde_json::from_slice(&frame.payload)
        .map_err(|e| format!("payload не JSON: {e}"))?;
    let cmd_id = v
        .get("cmd_id")
        .and_then(|c| c.as_u64())
        .ok_or("нет cmd_id")?;
    let waiter = {
        let mut p = state
            .pending
            .lock()
            .map_err(|_| "внутреннее состояние".to_string())?;
        p.remove(&cmd_id)
    };
    if let Some((tx, _)) = waiter {
        let outcome = if v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false) {
            Outcome::Ok(
                v.get("blob")
                    .and_then(|b| b.as_str())
                    .unwrap_or_default()
                    .to_string(),
            )
        } else {
            Outcome::Err(
                v.get("error")
                    .and_then(|b| b.as_str())
                    .unwrap_or("ошибка без текста")
                    .to_string(),
            )
        };
        let _ = tx.send(outcome);
    } else {
        eprintln!("poler-relay: RESULT cmd_id={cmd_id} без ждуна (таймаут?)");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP-фасад
// ---------------------------------------------------------------------------

struct HttpReq {
    method: String,
    path: String,
    auth: Option<String>,
    body: Vec<u8>,
    keep_alive: bool,
}

fn handle_http_conn(stream: TcpStream, state: &RelayState) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(HTTP_IDLE));
    let mut reader = match stream.try_clone() {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut writer = stream;
    loop {
        let req = match read_http_request(&mut reader, &mut writer) {
            Ok(Some(r)) => r,
            _ => return,
        };
        let keep = req.keep_alive;
        serve_http(&mut writer, req, state);
        if !keep {
            return;
        }
    }
}

fn read_http_request(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
) -> std::io::Result<Option<HttpReq>> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = http_find_header_end(&buf) {
            break pos;
        }
        if buf.len() > HTTP_HEADER_CAP {
            let _ = write_http(writer, 431, "text/plain", b"", false);
            return Ok(None);
        }
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().trim().to_string();
    if request_line.is_empty() {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default().to_string();
    let path = target.split('?').next().unwrap_or("/").to_string();
    let mut auth = None;
    let mut content_length = 0usize;
    let mut keep_alive = true;
    let mut expect_continue = false;
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            match k.as_str() {
                "authorization" => auth = Some(v.to_string()),
                "content-length" => content_length = v.parse().unwrap_or(0),
                "connection" => {
                    if v.eq_ignore_ascii_case("close") {
                        keep_alive = false;
                    }
                }
                "expect" => {
                    if v.eq_ignore_ascii_case("100-continue") {
                        expect_continue = true;
                    }
                }
                _ => {}
            }
        }
    }
    if content_length > HTTP_BODY_CAP {
        let _ = write_http(writer, 413, "text/plain", b"body too large", false);
        return Ok(None);
    }
    if expect_continue {
        let _ = writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        let _ = writer.flush();
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok(Some(HttpReq {
        method,
        path,
        auth,
        body,
        keep_alive,
    }))
}

fn http_find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn write_http(w: &mut TcpStream, status: u16, ctype: &str, body: &[u8], keep: bool) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n",
        body.len()
    );
    head.push_str(if keep {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(body)?;
    w.flush()
}

fn serve_http(w: &mut TcpStream, req: HttpReq, state: &RelayState) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/health") => {
            let online: Vec<String> = state
                .links
                .lock()
                .map(|l| l.keys().cloned().collect())
                .unwrap_or_default();
            let body = json!({
                "relay": state.cfg.relay.id,
                "version": env!("CARGO_PKG_VERSION"),
                "wire": WIRE_VERSION,
                "clients_online": online,
            });
            let b = serde_json::to_vec(&body).unwrap_or_default();
            let _ = write_http(w, 200, "application/json", &b, req.keep_alive);
        }
        ("POST", "/mcp") => serve_plain(w, req, state),
        ("POST", "/mcp-sealed") => serve_sealed(w, req, state),
        ("POST", _) | ("GET", _) => {
            let _ = write_http(
                w,
                404,
                "text/plain",
                b"not found (POST /mcp | POST /mcp-sealed | GET /health)",
                req.keep_alive,
            );
        }
        _ => {
            let _ = write_http(w, 405, "text/plain", b"method not allowed", req.keep_alive);
        }
    }
}

/// POST /mcp — plain-режим: Bearer + JSON-RPC (релей видит тело).
fn serve_plain(w: &mut TcpStream, req: HttpReq, state: &RelayState) {
    let token = req
        .auth
        .as_deref()
        .map(|a| a.trim_start_matches("Bearer").trim())
        .unwrap_or("");
    let client_id = match state.cfg.token_client(token) {
        Some(c) => c,
        None => {
            let _ = write_http(w, 401, "text/plain", b"bad or missing bearer token", req.keep_alive);
            return;
        }
    };
    let body_text = String::from_utf8_lossy(&req.body).into_owned();
    if serde_json::from_str::<Value>(&body_text).is_err() {
        let _ = write_http(w, 400, "text/plain", b"body is not valid JSON", req.keep_alive);
        return;
    }
    let cmd_id = match register_cmd(state, &client_id) {
        Some(id) => id,
        None => {
            let _ = write_http(w, 502, "text/plain", b"link client is not connected", req.keep_alive);
            return;
        }
    };
    let exec = json!({"mode": "plain", "cmd_id": cmd_id, "blob": body_text});
    let outcome = dispatch_exec(state, &client_id, cmd_id, &exec, req.keep_alive, w);
    let _ = outcome;
}

/// POST /mcp-sealed — конверт E2E: релей проверяет подпись над шифротекстом.
fn serve_sealed(w: &mut TcpStream, req: HttpReq, state: &RelayState) {
    let env: SealedEnvelope = match serde_json::from_slice(&req.body) {
        Ok(e) => e,
        Err(e) => {
            let msg = format!("конверт не разобран: {e}");
            let _ = write_http(w, 400, "text/plain", msg.as_bytes(), req.keep_alive);
            return;
        }
    };
    if env.v != WIRE_VERSION {
        let _ = write_http(w, 400, "text/plain", b"unsupported envelope version", req.keep_alive);
        return;
    }
    let reg = match state.cfg.find_agent(&env.from) {
        Some(r) => r.clone(),
        None => {
            let _ = write_http(w, 401, "text/plain", b"unknown agent", req.keep_alive);
            return;
        }
    };
    let agent_vk = match crate::keys::verify_key_from_b64(&reg.verify_key) {
        Ok(k) => k,
        Err(e) => {
            let msg = format!("конфиг агента: {e}");
            let _ = write_http(w, 500, "text/plain", msg.as_bytes(), req.keep_alive);
            return;
        }
    };
    // подпись над КАНОНИЧЕСКОЙ строкой (включает шифротекст — релей слеп)
    if let Err(e) = agent_vk.verify(envelope_canonical(&env).as_bytes(), &decode_sig(&env.sig)) {
        let _ = write_http(w, 401, "text/plain", format!("agent signature: {e}").as_bytes(), req.keep_alive);
        return;
    }
    let time = match env.time_u64() {
        Ok(t) => t,
        Err(_) => {
            let _ = write_http(w, 400, "text/plain", b"bad time", req.keep_alive);
            return;
        }
    };
    let nonce = match env.nonce_u64() {
        Ok(t) => t,
        Err(_) => {
            let _ = write_http(w, 400, "text/plain", b"bad nonce", req.keep_alive);
            return;
        }
    };
    if !time_in_window(time) {
        let _ = write_http(w, 401, "text/plain", b"envelope time outside window", req.keep_alive);
        return;
    }
    if let Err(e) = state.agent_check(&env.from, time, nonce) {
        let _ = write_http(w, 401, "text/plain", format!("replay: {e}").as_bytes(), req.keep_alive);
        return;
    }
    let cmd_id = match env.cmd_id_u64() {
        Ok(c) => c,
        Err(_) => {
            let _ = write_http(w, 400, "text/plain", b"bad cmd_id", req.keep_alive);
            return;
        }
    };
    // cmd_id в полёте?
    if let Ok(p) = state.pending.lock() {
        if p.contains_key(&cmd_id) {
            let _ = write_http(w, 409, "text/plain", b"cmd_id already in flight", req.keep_alive);
            return;
        }
    }
    let client_id = reg.client.clone();
    if state.link_of(&client_id).is_none() {
        let _ = write_http(w, 502, "text/plain", b"link client is not connected", req.keep_alive);
        return;
    }
    let blob = serde_json::to_string(&env).unwrap_or_default();
    let exec = json!({"mode": "sealed", "agent": env.from, "cmd_id": cmd_id, "blob": blob});
    dispatch_exec(state, &client_id, cmd_id, &exec, req.keep_alive, w);
}

fn decode_sig(b64: &str) -> ed25519_dalek::Signature {
    use ed25519_dalek::Signature;
    let raw = crate::keys::b64_decode(b64).unwrap_or_default();
    Signature::from_slice(&raw).unwrap_or(Signature::from_bytes(&[0u8; 64]))
}

/// Зарегистрировать ждуна и отправить EXEC линк-клиенту.
fn dispatch_exec(
    state: &RelayState,
    client_id: &str,
    cmd_id: u64,
    exec: &Value,
    keep_alive: bool,
    w: &mut TcpStream,
) {
    let (tx, rx): (Sender<Outcome>, Receiver<Outcome>) = mpsc::channel();
    {
        let mut p = match state.pending.lock() {
            Ok(p) => p,
            Err(_) => {
                let _ = write_http(w, 500, "text/plain", b"internal state", keep_alive);
                return;
            }
        };
        p.insert(cmd_id, (tx, client_id.to_string()));
    }
    let sent = state.link_of(client_id).and_then(|(link_tx, session)| {
        let payload = serde_json::to_vec(exec).unwrap_or_default();
        let frame = session.seal(FT_EXEC, cmd_id, wire::new_nonce(), &payload);
        link_tx.send(frame).ok()
    });
    if sent.is_none() {
        if let Ok(mut p) = state.pending.lock() {
            p.remove(&cmd_id);
        }
        let _ = write_http(w, 502, "text/plain", b"link client is not connected", keep_alive);
        return;
    }
    let timeout = Duration::from_millis(state.cfg.relay.exec_timeout_ms.max(1_000));
    match rx.recv_timeout(timeout) {
        Ok(Outcome::Ok(blob)) => {
            if blob.is_empty() {
                // MCP-уведомление: ответа не будет
                let _ = write_http(w, 202, "text/plain", b"", keep_alive);
            } else {
                let ctype = if blob.starts_with('{') {
                    "application/json"
                } else {
                    "text/plain"
                };
                let _ = write_http(w, 200, ctype, blob.as_bytes(), keep_alive);
            }
        }
        Ok(Outcome::Err(e)) => {
            let status = if e.contains("отключён") || e.contains("запись") { 502 } else { 500 };
            let _ = write_http(w, status, "text/plain", e.as_bytes(), keep_alive);
        }
        Err(_) => {
            if let Ok(mut p) = state.pending.lock() {
                p.remove(&cmd_id);
            }
            let _ = write_http(w, 504, "text/plain", b"exec timeout", keep_alive);
        }
    }
}

/// Уникальный cmd_id для plain-режима; None — клиент не подключён.
fn register_cmd(state: &RelayState, client_id: &str) -> Option<u64> {
    if state.link_of(client_id).is_none() {
        return None;
    }
    let p = state.pending.lock().ok()?;
    for _ in 0..8 {
        let id = wire::new_cmd_id();
        if !p.contains_key(&id) {
            return Some(id);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Identity;

    fn sample_cfg() -> RelayCfg {
        let id = Identity::generate();
        let token = "poler_mesh_test_token";
        RelayCfg {
            relay: RelaySection {
                id: "relay-1".into(),
                bind: "127.0.0.1:0".into(),
                http: "127.0.0.1:0".into(),
                exec_timeout_ms: 2000,
            },
            keys: KeysSection {
                identity_seed: crate::keys::b64_encode(id.signing.as_bytes()),
            },
            clients: vec![ClientReg {
                id: "main".into(),
                verify_key: id.verify_key_b64(),
                box_key: id.box_public_b64(),
            }],
            agents: vec![AgentReg {
                id: "glm".into(),
                verify_key: id.verify_key_b64(),
                client: "main".into(),
            }],
            tokens: vec![TokenReg {
                hash: token_sha256(token),
                client: "main".into(),
            }],
        }
    }

    #[test]
    fn config_parse_roundtrip() {
        let cfg = sample_cfg();
        let text = example_toml(
            &cfg.relay.id,
            &cfg.keys.identity_seed,
            &token_sha256("x"),
        );
        // example_toml содержит плейсхолдеры ключей — парсим его с ними
        let parsed = RelayCfg::parse(&text).unwrap();
        assert_eq!(parsed.relay.id, "relay-1");
        assert_eq!(parsed.relay.bind, "0.0.0.0:8771");
        assert_eq!(parsed.clients.len(), 1);
        assert_eq!(parsed.agents[0].client, "main");
    }

    #[test]
    fn token_hash_and_lookup() {
        let cfg = sample_cfg();
        assert_eq!(cfg.token_client("poler_mesh_test_token").unwrap(), "main");
        assert!(cfg.token_client("wrong").is_none());
        assert_ne!(token_sha256("a"), token_sha256("b"));
        assert_eq!(token_sha256("x").len(), 64);
    }

    #[test]
    fn token_hash_is_sha256_hex() {
        assert_eq!(
            token_sha256("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn find_client_and_agent() {
        let cfg = sample_cfg();
        assert!(cfg.find_client("main").is_some());
        assert!(cfg.find_client("ghost").is_none());
        assert!(cfg.find_agent("glm").is_some());
        assert!(cfg.find_agent("ghost").is_none());
    }

    #[test]
    fn http_find_header_end_works() {
        assert_eq!(http_find_header_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"), Some(27));
        assert_eq!(http_find_header_end(b"no end"), None);
    }
}
