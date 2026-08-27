//! # Хаб поверх HTTP (Streamable HTTP transport)
//!
//! `poler-mesh --mcp-http 127.0.0.1:8770 --mcp-token <секрет>`
//!
//! Один и тот же контракт, что у узлов (poler-engine/poler-git
//! `--mcp-http`): JSON-RPC 2.0, POST `/` или `/mcp`, bearer-токен.
//! Разница — за токеном теперь ВСЯ сетка, а не один узел:
//! агент видит объединённый tools/list и вызывает любой инструмент.
//!
//! Наружу — через туннель: `cloudflared tunnel --url http://127.0.0.1:8770`.
//!
//! Транспорт: ручной HTTP/1.1 поверх std::net — ноль зависимостей,
//! keep-alive, потолки на заголовки/тело, лимит соединений.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::hub::Hub;

const MAX_CONNS: usize = 16;
const HEADER_CAP: usize = 16 * 1024;
const BODY_CAP: usize = 8 * 1024 * 1024;
const IDLE: Duration = Duration::from_secs(65);

/// Запуск хаба по HTTP. Блокируется до ошибки акцептора.
pub fn run_http(bind: &str, token: &str, nodes_cfg: &[crate::config::NodeCfg]) -> i32 {
    let bind = match bind.parse::<u16>() {
        Ok(port) => format!("127.0.0.1:{port}"),
        Err(_) => bind.to_string(),
    };
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("poler-mesh-http: не удалось занять {bind}: {e}");
            return 2;
        }
    };
    let actual = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.clone());
    // хаб один на всех соединений (узлы-процессы дорогие — не плодим)
    let hub = match Hub::build(nodes_cfg) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("poler-mesh-http: {e}");
            return 2;
        }
    };
    eprintln!("poler-mesh-http: слушаю http://{actual}   (POST /  или  POST /mcp; GET /health)");
    eprintln!("poler-mesh-http: TOKEN: {token}");
    eprintln!();
    eprintln!("POLER_MESH_HTTP_BIND: {actual}");
    eprintln!("Удалённый доступ для агента (дай ему эти две строки):");
    eprintln!("  URL:       https://<твой-туннель>/mcp");
    eprintln!("  Заголовок: Authorization: Bearer {token}");
    eprintln!("Туннель без аккаунта: cloudflared tunnel --url http://{actual}");
    let hub = Arc::new(Mutex::new(hub));
    serve(listener, hub, token)
}

fn serve(listener: TcpListener, hub: Arc<Mutex<Hub>>, token: &str) -> i32 {
    let token = token.to_string();
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        if active.load(Ordering::Relaxed) >= MAX_CONNS {
            let mut w = stream;
            let _ = write_response(&mut w, 503, "text/plain", b"too many connections", false, &[]);
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let hub = Arc::clone(&hub);
        let token = token.clone();
        let active = Arc::clone(&active);
        thread::spawn(move || {
            handle_conn(stream, &hub, &token);
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    0
}

fn handle_conn(stream: TcpStream, hub: &Arc<Mutex<Hub>>, token: &str) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(IDLE));
    let mut reader = match stream.try_clone() {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut writer = stream;
    loop {
        let req = match read_request(&mut reader, &mut writer) {
            Ok(Some(r)) => r,
            _ => return,
        };
        let keep = req.keep_alive;
        respond(&mut writer, req, hub, token);
        if !keep {
            return;
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    auth: Option<String>,
    body: Vec<u8>,
    keep_alive: bool,
}

fn read_request(reader: &mut TcpStream, writer: &mut TcpStream) -> std::io::Result<Option<HttpRequest>> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > HEADER_CAP {
            let _ = write_response(writer, 431, "text/plain", b"", false, &[]);
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
    if content_length > BODY_CAP {
        let _ = write_response(writer, 413, "text/plain", b"body too large", false, &[]);
        return Ok(None);
    }
    if expect_continue {
        let _ = writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        let _ = writer.flush();
    }
    let already = buf.len() - header_end;
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length.max(already.min(content_length)));
    Ok(Some(HttpRequest {
        method,
        path,
        auth,
        body,
        keep_alive,
    }))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn respond(w: &mut TcpStream, req: HttpRequest, hub: &Arc<Mutex<Hub>>, token: &str) {
    // health-check без авторизации — удобно для проверки туннеля
    if req.method == "GET" && (req.path == "/health" || req.path == "/") {
        let body = format!(
            "poler-mesh {} — узлов: {}\n",
            env!("CARGO_PKG_VERSION"),
            hub.lock().map(|h| h.nodes.len()).unwrap_or(0)
        );
        let _ = write_response(w, 200, "text/plain", body.as_bytes(), req.keep_alive, &[]);
        return;
    }
    if req.method != "POST" || (req.path != "/" && req.path != "/mcp") {
        let _ = write_response(w, 404, "text/plain", b"not found (POST / or /mcp)", req.keep_alive, &[]);
        return;
    }
    let ok_auth = match &req.auth {
        Some(a) => a.trim_start_matches("Bearer").trim() == token,
        None => false,
    };
    if !ok_auth {
        let _ = write_response(w, 401, "text/plain", b"bad or missing bearer token", req.keep_alive, &[]);
        return;
    }
    let parsed: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("bad JSON: {e}");
            let _ = write_response(w, 400, "text/plain", msg.as_bytes(), req.keep_alive, &[]);
            return;
        }
    };
    // одна строка = один JSON-RPC вызов (batch — v0.2)
    let resp = match hub.lock() {
        Ok(mut h) => h.dispatch(&parsed),
        Err(_) => Some(json!({
            "jsonrpc":"2.0","id":Value::Null,
            "error":{"code":-32603,"message":"poler-mesh: внутреннее состояние недоступно"}
        })),
    };
    match resp {
        Some(r) => {
            let body = serde_json::to_vec(&r).unwrap_or_default();
            let _ = write_response(w, 200, "application/json", &body, req.keep_alive, &[]);
        }
        // уведомление: принято, отвечать нечем (MCP Streamable HTTP: 202)
        None => {
            let _ = write_response(w, 202, "text/plain", b"", req.keep_alive, &[]);
        }
    }
}

fn write_response(
    w: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
    keep: bool,
    extra: &[(&str, &str)],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "OK",
    };
    let mut head = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n", body.len());
    head.push_str(if keep {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// Сгенерировать токен: /dev/urandom → hex; фолбэк — время+pid.
pub fn generate_token() -> String {
    let mut b = [0u8; 16];
    let mut ok = false;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        ok = f.read_exact(&mut b).is_ok();
    }
    if !ok {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = ((t >> (i * 4)) ^ (pid >> (i * 3))) as u8;
        }
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_32_hex_chars() {
        let t = generate_token();
        assert_eq!(t.len(), 32);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn find_header_end_works() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"), Some(27));
        assert_eq!(find_header_end(b"no header end"), None);
    }
}
