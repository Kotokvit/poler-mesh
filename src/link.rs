//! # link-клиент: poler-mesh --mcp-link (docs/wire.md)
//!
//! Машина владельца САМА подключается к poler-relay (исходящее соединение:
//! NAT неважен, входящих портов нет). Handshake → AEAD-сессия → читаем EXEC,
//! исполняем через локальный [`Hub`], отвечаем RESULT. Обрыв — реконнект
//! с экспоненциальным бэкоффом и джиттером, бесконечно.
//!
//! Sealed-режим: конверт агента расшифровывается нашим X25519-static,
//! подпись агента сверяется с доверенным списком; ответ запечатывается
//! обратно на эфемерный ключ агента. Идемпотентность — кэш cmd_id (TTL 300 c).

use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ed25519_dalek::{Signer, VerifyingKey};
use serde_json::{json, Value};
use x25519_dalek::PublicKey as XPub;

use crate::config::NodeCfg;
use crate::hub::Hub;
use crate::keys::{
    open_envelope, seal_envelope, Identity, SealedEnvelope,
};
use crate::wire::{
    self, ephemeral, hello_ack_canonical, hello_canonical, x25519_pub, x25519_pub_b64,
    Frame, Hello, HelloAck, IdemCache, ReplayGuard, Session, FT_ERROR, FT_EXEC, FT_HELLO,
    FT_HELLO_ACK, FT_PING, FT_PONG, FT_RESULT, WIRE_VERSION,
};

/// Пинг клиенту→релею: держит NAT-маппинг живым.
const PING_EVERY: Duration = Duration::from_secs(25);
/// Простой чтения до разрыва (релей пингует каждые 25 c).
const READ_IDLE: Duration = Duration::from_secs(90);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Потолок бэкоффа.
const BACKOFF_CAP: Duration = Duration::from_secs(60);

/// Настройки link-режима.
pub struct LinkOpts {
    /// host:port релея (client-leg).
    pub addr: String,
    /// Идентичность клиента (Ed25519 + X25519 static).
    pub identity: Identity,
    /// id клиента, зарегистрированный в конфиге релея.
    pub client_id: String,
    /// Пиннинг публичного Ed25519-ключа релея.
    pub relay_verify: VerifyingKey,
    /// Доверенные агенты: id → Ed25519 verify-key.
    pub trusted_agents: HashMap<String, VerifyingKey>,
}

struct LinkRuntime {
    opts: LinkOpts,
    hub: Arc<Mutex<Hub>>,
    idem: Mutex<IdemCache>,
    agent_replay: Mutex<HashMap<String, ReplayGuard>>,
}

/// Запустить link-режим. Блокируется навсегда (бесконечный реконнект).
pub fn run_link(opts: LinkOpts, nodes: &[NodeCfg]) -> i32 {
    let hub = match Hub::build(nodes) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("poler-mesh-link: {e}");
            return 2;
        }
    };
    let hub = Arc::new(Mutex::new(hub));
    let rt = Arc::new(LinkRuntime {
        opts,
        hub,
        idem: Mutex::new(IdemCache::new()),
        agent_replay: Mutex::new(HashMap::new()),
    });

    eprintln!(
        "poler-mesh-link: подключаюсь к {} (клиент «{}», доверенных агентов: {})",
        rt.opts.addr, rt.opts.client_id, rt.opts.trusted_agents.len()
    );
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect_and_serve(&rt) {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(e) => eprintln!("poler-mesh-link: {e}"),
        }
        eprintln!("poler-mesh-link: реконнект через {:?}…", backoff);
        thread::sleep(jitter(backoff));
        backoff = std::cmp::min(backoff * 2, BACKOFF_CAP);
    }
}

fn jitter(d: Duration) -> Duration {
    let ms = d.as_millis() as u64;
    let j = (wire::os_random_u64() % (ms / 5 + 1).max(1)).saturating_sub(ms / 10);
    Duration::from_millis(ms + j)
}

/// Одна жизнь соединения: handshake + обслуживание. Err — причина разрыва.
fn connect_and_serve(rt: &Arc<LinkRuntime>) -> Result<(), String> {
    let stream = TcpStream::connect(&rt.opts.addr)
        .map_err(|e| format!("connect {}: {e}", rt.opts.addr))?;
    stream
        .set_nodelay(true)
        .map_err(|e| format!("nodelay: {e}"))?;
    let mut reader = stream
        .try_clone()
        .map_err(|e| format!("clone reader: {e}"))?;
    reader
        .set_read_timeout(Some(READ_IDLE))
        .map_err(|e| format!("read timeout: {e}"))?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| format!("clone writer: {e}"))?;
    writer
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|e| format!("write timeout: {e}"))?;

    // --- handshake ---
    let (eph_secret, eph_pub) = ephemeral();
    let hello = Hello {
        v: WIRE_VERSION,
        client_id: rt.opts.client_id.clone(),
        eph: x25519_pub_b64(&eph_pub),
        time: crate::keys::now_unix(),
        nonce: wire::new_nonce(),
        sig: String::new(),
    };
    let hello = {
        let sig = rt.opts.identity.signing.sign(hello_canonical(&hello).as_bytes());
        Hello {
            sig: crate::keys::b64_encode(&sig.to_bytes()),
            ..hello
        }
    };
    let hello_bytes =
        serde_json::to_vec(&hello).map_err(|e| format!("hello json: {e}"))?;
    writer
        .write_all(&wire::encode_plain_frame(&Frame::plain(FT_HELLO, &hello_bytes)))
        .map_err(|e| format!("отправка HELLO: {e}"))?;

    let ack_raw = wire::read_raw_frame(&mut reader)?;
    let (ft, _, _, _, _) = wire::parse_header(&ack_raw)?;
    if ft != FT_HELLO_ACK {
        return Err(format!("ожидался HELLO_ACK, пришёл 0x{ft:02x}"));
    }
    let ack: HelloAck = serde_json::from_slice(&ack_raw[33..])
        .map_err(|e| format!("HELLO_ACK json: {e}"))?;
    if ack.v != WIRE_VERSION {
        return Err(format!("версия релея {} ≠ {WIRE_VERSION}", ack.v));
    }
    // пиннинг релея
    let ack_eph: XPub = x25519_pub(&ack.eph)?;
    crate::keys::verify_sig(
        &rt.opts.relay_verify,
        &hello_ack_canonical(&ack, &hello.eph),
        &ack.sig,
    )
    .map_err(|e| format!("подпись релея (пиннинг): {e}"))?;

    let shared = *eph_secret.diffie_hellman(&ack_eph).as_bytes();
    let (c2r, r2c) = wire::derive_session(&shared, eph_pub.as_bytes(), ack_eph.as_bytes())?;
    let session = Arc::new(Session::client_side(c2r, r2c));

    // --- writer-тред + пингер ---
    let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
    {
        let mut w = writer;
        thread::spawn(move || {
            while let Ok(bytes) = rx.recv() {
                if bytes.is_empty() {
                    return;
                }
                if w.write_all(&bytes).is_err() {
                    return;
                }
            }
        });
    }
    let ping_tx = tx.clone();
    let ping_session = Arc::clone(&session);
    thread::spawn(move || loop {
        thread::sleep(PING_EVERY);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let payload = format!("{{\"t\":{now_ms}}}");
        if ping_tx
            .send(ping_session.seal(FT_PING, 0, wire::new_nonce(), payload.as_bytes()))
            .is_err()
        {
            return;
        }
    });

    eprintln!(
        "poler-mesh-link: на связи с релеем «{}» ({})",
        ack.relay_id, rt.opts.addr
    );

    // --- reader-цикл ---
    loop {
        let raw = wire::read_raw_frame(&mut reader)?;
        let frame = session.open(&raw)?;
        match frame.ft {
            FT_PING => {
                let pong = session.seal(FT_PONG, frame.cmd_id, frame.nonce, &frame.payload);
                if tx.send(pong).is_err() {
                    return Err("writer-канал закрыт".into());
                }
            }
            FT_PONG => { /* релей жив; мерить RTT можно по payload */ }
            FT_EXEC => {
                if let Err(e) = serve_exec(rt, &session, &tx, &frame) {
                    eprintln!("poler-mesh-link: exec: {e}");
                    let err_payload = json!({"cmd_id": frame.cmd_id, "ok": false, "error": e});
                    let out = session.seal(
                        FT_RESULT,
                        frame.cmd_id,
                        frame.nonce,
                        err_payload.to_string().as_bytes(),
                    );
                    if tx.send(out).is_err() {
                        return Err("writer-канал закрыт".into());
                    }
                }
            }
            FT_ERROR => {
                eprintln!("poler-mesh-link: релей: {}", frame.payload_str());
            }
            FT_HELLO | FT_RESULT | FT_HELLO_ACK => {
                eprintln!(
                    "poler-mesh-link: неожиданный кадр 0x{:02x} от релея",
                    frame.ft
                );
            }
            _ => {}
        }
    }
}

/// Обработать EXEC: plain (MCP напрямую) или sealed (конверт агента).
fn serve_exec(
    rt: &Arc<LinkRuntime>,
    session: &Arc<Session>,
    tx: &Sender<Vec<u8>>,
    frame: &Frame,
) -> Result<(), String> {
    let v: Value = serde_json::from_slice(&frame.payload)
        .map_err(|e| format!("exec payload не JSON: {e}"))?;
    let cmd_id = v
        .get("cmd_id")
        .and_then(|c| c.as_u64())
        .ok_or("нет cmd_id")?;
    let mode = v.get("mode").and_then(|m| m.as_str()).unwrap_or("plain");
    let blob = v.get("blob").and_then(|b| b.as_str()).unwrap_or("");

    // ВАЖНО: MutexGuard из if-let-scrutinee живёт до конца if/else (Rust ≤2021)
    // — берём и отпускаем lock ЯВНО, до захвата повторно (анти-deadlock).
    let (result, notify) = match mode {
        "sealed" => {
            let env: SealedEnvelope = serde_json::from_str(blob)
                .map_err(|e| format!("конверт не разобран: {e}"))?;
            (serve_sealed_exec(rt, cmd_id, env)?, false)
        }
        _ => {
            let cached = {
                let mut idem = rt.idem.lock().map_err(poison)?;
                idem.get(cmd_id)
            };
            if let Some(text) = cached {
                (text, false)
            } else {
                let req: Value = serde_json::from_str(blob)
                    .map_err(|e| format!("MCP-запрос не JSON: {e}"))?;
                let resp = dispatch_hub(rt, &req);
                match resp {
                    Some(r) => {
                        let text = serde_json::to_string(&r).unwrap_or_default();
                        rt.idem.lock().map_err(poison)?.put(cmd_id, text.clone());
                        (text, false)
                    }
                    None => (String::new(), true), // уведомление
                }
            }
        }
    };

    let payload = if notify {
        json!({"cmd_id": cmd_id, "ok": true, "blob": ""}).to_string()
    } else {
        json!({"cmd_id": cmd_id, "ok": true, "blob": result}).to_string()
    };
    let out = session.seal(FT_RESULT, frame.cmd_id, frame.nonce, payload.as_bytes());
    tx.send(out).map_err(|_| "writer-канал закрыт".into())
}

/// Sealed-исполнение: идемпотентность → replay → расшифровка → Hub → ответ-конверт.
fn serve_sealed_exec(
    rt: &Arc<LinkRuntime>,
    cmd_id: u64,
    env: SealedEnvelope,
) -> Result<String, String> {
    // 1. идемпотентность: повтор cmd_id отдаёт кэш, заново запечатанный под eph
    let cached = rt.idem.lock().map_err(poison)?.get(cmd_id);
    if let Some(text) = cached {
        return seal_response(rt, &env, cmd_id, &text);
    }

    // 2. агент доверенный?
    let vk = rt
        .opts
        .trusted_agents
        .get(&env.from)
        .ok_or(format!("агент «{}» не в доверенном списке", env.from))?
        .clone();

    // 3. replay-фильтр (только для новых cmd_id)
    let time = env.time_u64()?;
    let nonce = env.nonce_u64()?;
    rt.agent_replay
        .lock()
        .map_err(poison)?
        .entry(env.from.clone())
        .or_insert_with(ReplayGuard::new)
        .check(time, nonce)?;

    // 4. расшифровка + подпись
    let mcp_text = open_envelope(&env, &rt.opts.identity.box_static, &vk)?;

    // 5. исполнение через Hub
    let req: Value = serde_json::from_str(&mcp_text)
        .map_err(|e| format!("MCP-запрос не JSON: {e}"))?;
    let resp = dispatch_hub(rt, &req)
        .ok_or("уведомление в sealed-режиме не поддерживается")?;
    let result_text = serde_json::to_string(&resp).unwrap_or_default();

    // 6. кэш идемпотентности и ответ-конверт на eph агента
    rt.idem
        .lock()
        .map_err(poison)?
        .put(cmd_id, result_text.clone());
    seal_response(rt, &env, cmd_id, &result_text)
}

/// Запечатать ответ агенту (на его eph) и подписать своей идентичностью.
fn seal_response(
    rt: &Arc<LinkRuntime>,
    env: &SealedEnvelope,
    cmd_id: u64,
    text: &str,
) -> Result<String, String> {
    let (resp, _) = seal_envelope(
        &rt.opts.client_id,
        &env.eph,
        cmd_id,
        wire::new_nonce(),
        text,
        &rt.opts.identity.signing,
    )?;
    serde_json::to_string(&resp).map_err(|e| format!("конверт ответа: {e}"))
}

fn dispatch_hub(rt: &Arc<LinkRuntime>, req: &Value) -> Option<Value> {
    match rt.hub.lock() {
        Ok(mut hub) => hub.dispatch(req),
        Err(_) => Some(json!({
            "jsonrpc":"2.0","id":Value::Null,
            "error":{"code":-32603,"message":"poler-mesh: внутреннее состояние недоступно"}
        })),
    }
}

fn poison<T>(_: T) -> String {
    "внутреннее состояние недоступно".into()
}

/// Разобрать список доверенных агентов из "id=b64" / "id:b64" (запятые).
pub fn parse_trusted_agents(specs: &[String]) -> Result<HashMap<String, VerifyingKey>, String> {
    let mut out = HashMap::new();
    for spec in specs {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            // ':' приоритетнее '=': b64-паддинг заканчивается на '=' и ломает
            // разбор «id=ключ» (docs/wire.md §4)
            let (id, key) = part
                .split_once(':')
                .or_else(|| part.split_once('='))
                .ok_or_else(|| format!("агент задаётся как ID=B64: {part}"))?;
            let vk = crate::keys::verify_key_from_b64(key.trim())
                .map_err(|e| format!("агент «{}»: {e}", id.trim()))?;
            out.insert(id.trim().to_string(), vk);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trusted_agents_ok_and_err() {
        let id = Identity::generate();
        let spec = format!("glm={}", id.verify_key_b64());
        let map = parse_trusted_agents(&[spec]).unwrap();
        assert!(map.contains_key("glm"));

        let two = format!("a={}, b:{}", id.verify_key_b64(), id.verify_key_b64());
        assert_eq!(parse_trusted_agents(&[two]).unwrap().len(), 2);
        assert!(parse_trusted_agents(&["bad".into()]).is_err());
        assert!(parse_trusted_agents(&[format!("x={}", "AAAA")]).is_err());
    }

    #[test]
    fn jitter_stays_near_base() {
        let base = Duration::from_secs(2);
        for _ in 0..50 {
            let j = jitter(base);
            assert!(j >= Duration::from_millis(1900) && j <= Duration::from_millis(2400));
        }
    }
}
