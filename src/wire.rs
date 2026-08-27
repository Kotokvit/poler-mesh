//! # poler-wire v1: кадры и сессия client-leg
//!
//! Голый TCP, length-prefixed кадры (docs/wire.md §2):
//! `[len u32][type u8][cmd_id u64][nonce u64][time u64][seq u64][ciphertext]`.
//! После handshake (§3) всё шифруется ChaCha20-Poly1305 с ключами направлений;
//! `seq` строго монотонный и входит в AEAD-nonce. HELLO/HELLO_ACK — открытый JSON.

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSecret};

use crate::keys::{b64_decode, b64_encode, now_unix, random_32, random_u64};

/// Версия протокола poler-wire.
pub const WIRE_VERSION: u8 = 1;

pub const FT_HELLO: u8 = 0x01;
pub const FT_EXEC: u8 = 0x02;
pub const FT_RESULT: u8 = 0x03;
pub const FT_PING: u8 = 0x04;
pub const FT_PONG: u8 = 0x05;
pub const FT_ERROR: u8 = 0x06;
pub const FT_HELLO_ACK: u8 = 0x07;

/// Потолок размера кадра (16 МБ).
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Допуск времени в секундах (±300 c).
pub const TIME_SKEW: u64 = 300;

// ---------------------------------------------------------------------------
// Кадр
// ---------------------------------------------------------------------------

/// Расшифрованный/открытый кадр.
#[derive(Debug, Clone)]
pub struct Frame {
    pub ft: u8,
    pub cmd_id: u64,
    pub nonce: u64,
    pub time: u64,
    pub seq: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Открытый кадр (HELLO/HELLO_ACK): seq=0, без шифрования.
    pub fn plain(ft: u8, payload: &[u8]) -> Frame {
        Frame {
            ft,
            cmd_id: 0,
            nonce: 0,
            time: 0,
            seq: 0,
            payload: payload.to_vec(),
        }
    }

    pub fn payload_str(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }

    pub fn payload_json(&self) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&self.payload).map_err(|e| format!("payload не JSON: {e}"))
    }
}

/// Закодировать открытый (незашифрованный) кадр в байты с длиной.
pub fn encode_plain_frame(f: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 33 + f.payload.len());
    out.extend_from_slice(&((33 + f.payload.len()) as u32).to_be_bytes());
    out.push(f.ft);
    out.extend_from_slice(&f.cmd_id.to_be_bytes());
    out.extend_from_slice(&f.nonce.to_be_bytes());
    out.extend_from_slice(&f.time.to_be_bytes());
    out.extend_from_slice(&f.seq.to_be_bytes());
    out.extend_from_slice(&f.payload);
    out
}

/// Прочитать сырые байты кадра из потока: [len u32][тело]. Шифротекст
/// расшифровывает вызывающий (у него сессия).
pub fn read_raw_frame(r: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut len_b = [0u8; 4];
    r.read_exact(&mut len_b).map_err(|e| format!("чтение len: {e}"))?;
    let len = u32::from_be_bytes(len_b) as usize;
    if len < 33 || len > MAX_FRAME {
        return Err(format!("кадр недопустимой длины: {len}"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|e| format!("чтение тела: {e}"))?;
    Ok(body)
}

/// Разобрать заголовок сырого кадра (первые 33 байта) → (ft, cmd_id, nonce, time, seq).
pub fn parse_header(body: &[u8]) -> Result<(u8, u64, u64, u64, u64), String> {
    if body.len() < 33 {
        return Err("кадр короче заголовка".into());
    }
    let ft = body[0];
    let arr8 = |s: usize| -> [u8; 8] { body[s..s + 8].try_into().unwrap() };
    Ok((
        ft,
        u64::from_be_bytes(arr8(1)),
        u64::from_be_bytes(arr8(9)),
        u64::from_be_bytes(arr8(17)),
        u64::from_be_bytes(arr8(25)),
    ))
}

// ---------------------------------------------------------------------------
// Сессия (ключи направлений после handshake)
// ---------------------------------------------------------------------------

/// Направление сессии: ключ + монотонный счётчик (atomic —.Writer и reader
/// живут в разных тредах).
pub struct WireHalf {
    key: [u8; 32],
    seq: AtomicU64,
}

impl WireHalf {
    fn new(key: [u8; 32]) -> WireHalf {
        WireHalf {
            key,
            seq: AtomicU64::new(0),
        }
    }
}

/// AEAD-сессия обеих сторон handshake.
pub struct Session {
    pub send: WireHalf,
    pub recv: WireHalf,
    /// Последний принятый seq (строгая монотонность).
    last_recv: AtomicU64,
}

/// Вывести ключи направлений из общего секрета и публичных ключей handshake.
///
/// c2r — от клиента к релею, r2c — обратно. Каждая сторона инициализирует
/// Session своими send/recv.
pub fn derive_session(
    shared: &[u8; 32],
    hello_eph: &[u8; 32],
    ack_eph: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), String> {
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};
    let mut salt_src = b"poler-wire-v1".to_vec();
    salt_src.extend_from_slice(hello_eph);
    salt_src.extend_from_slice(ack_eph);
    let salt = Sha256::digest(&salt_src);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut c2r = [0u8; 32];
    let mut r2c = [0u8; 32];
    hk.expand(b"poler-wire/c2r", &mut c2r)
        .map_err(|e| format!("hkdf c2r: {e}"))?;
    hk.expand(b"poler-wire/r2c", &mut r2c)
        .map_err(|e| format!("hkdf r2c: {e}"))?;
    Ok((c2r, r2c))
}

impl Session {
    /// Сессия стороны клиента: send=c2r, recv=r2c.
    pub fn client_side(c2r: [u8; 32], r2c: [u8; 32]) -> Session {
        Session {
            send: WireHalf::new(c2r),
            recv: WireHalf::new(r2c),
            last_recv: AtomicU64::new(0),
        }
    }

    /// Сессия стороны релея: send=r2c, recv=c2r.
    pub fn relay_side(c2r: [u8; 32], r2c: [u8; 32]) -> Session {
        Session {
            send: WireHalf::new(r2c),
            recv: WireHalf::new(c2r),
            last_recv: AtomicU64::new(0),
        }
    }

    fn aead_nonce(seq: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seq.to_be_bytes());
        n
    }

    /// Зашифровать кадр и закодировать с длиной (инкрементирует send.seq).
    pub fn seal(&self, ft: u8, cmd_id: u64, nonce: u64, plaintext: &[u8]) -> Vec<u8> {
        let seq = self.send.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let time = now_unix();
        let mut head = Vec::with_capacity(33);
        head.push(ft);
        head.extend_from_slice(&cmd_id.to_be_bytes());
        head.extend_from_slice(&nonce.to_be_bytes());
        head.extend_from_slice(&time.to_be_bytes());
        head.extend_from_slice(&seq.to_be_bytes());

        let cipher = ChaCha20Poly1305::new((&self.send.key).into());
        let ct = cipher
            .encrypt(
                &Self::aead_nonce(seq).into(),
                Payload {
                    msg: plaintext,
                    aad: &head,
                },
            )
            .expect("seal");

        let mut out = Vec::with_capacity(4 + head.len() + ct.len());
        out.extend_from_slice(&((head.len() + ct.len()) as u32).to_be_bytes());
        out.extend_from_slice(&head);
        out.extend_from_slice(&ct);
        out
    }

    /// Расшифровать сырой кадр (байты после поля len). Строгая монотонность seq.
    pub fn open(&self, body: &[u8]) -> Result<Frame, String> {
        let (ft, cmd_id, nonce, time, seq) = parse_header(body)?;
        if ft == FT_HELLO || ft == FT_HELLO_ACK {
            return Ok(Frame {
                ft,
                cmd_id,
                nonce,
                time,
                seq,
                payload: body[33..].to_vec(),
            });
        }
        // строгая монотонность
        let mut last = self.last_recv.load(Ordering::SeqCst);
        loop {
            if seq <= last {
                return Err(format!("seq не возрастает ({seq} ≤ {last}) — replay?"));
            }
            match self.last_recv.compare_exchange(
                last,
                seq,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(cur) => last = cur,
            }
        }
        let cipher = ChaCha20Poly1305::new((&self.recv.key).into());
        let head = &body[..33];
        let pt = cipher
            .decrypt(
                &Self::aead_nonce(seq).into(),
                Payload {
                    msg: &body[33..],
                    aad: head,
                },
            )
            .map_err(|_| "AEAD: неверный ключ или повреждён кадр".to_string())?;
        Ok(Frame {
            ft,
            cmd_id,
            nonce,
            time,
            seq,
            payload: pt,
        })
    }
}

// ---------------------------------------------------------------------------
// Handshake-сообщения
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub struct Hello {
    pub v: u8,
    pub client_id: String,
    pub eph: String,
    pub time: u64,
    pub nonce: u64,
    pub sig: String,
}

pub fn hello_canonical(h: &Hello) -> String {
    format!(
        "poler-wire-hello-v1|{}|{}|{}|{}|{}",
        h.v, h.client_id, h.eph, h.time, h.nonce
    )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HelloAck {
    pub v: u8,
    pub relay_id: String,
    pub eph: String,
    pub sig: String,
}

pub fn hello_ack_canonical(a: &HelloAck, hello_eph: &str) -> String {
    format!(
        "poler-wire-helloack-v1|{}|{}|{}|{}",
        a.v, a.relay_id, a.eph, hello_eph
    )
}

/// Свежесть handshake: время в окне ±TIME_SKEW.
pub fn time_in_window(t: u64) -> bool {
    let now = now_unix();
    t + TIME_SKEW >= now && now + TIME_SKEW >= t
}

// ---------------------------------------------------------------------------
// Replay-фильтр и кэш идемпотентности
// ---------------------------------------------------------------------------

/// Фильтр повторов: nonce c TTL = окно времени. Прунится лениво.
pub struct ReplayGuard {
    seen: HashMap<u64, u64>,
    skew: u64,
}

impl ReplayGuard {
    pub fn new() -> ReplayGuard {
        ReplayGuard {
            seen: HashMap::new(),
            skew: TIME_SKEW,
        }
    }

    /// Проверить и зарегистрировать (time, nonce). Err — replay или протухло.
    pub fn check(&mut self, time: u64, nonce: u64) -> Result<(), String> {
        let now = now_unix();
        if time + self.skew < now || now + self.skew < time {
            return Err(format!(
                "время вне окна ±{}с (time={time}, now={now})",
                self.skew
            ));
        }
        if self.seen.contains_key(&nonce) {
            return Err(format!("nonce {nonce} уже был — replay"));
        }
        self.prune(now);
        self.seen.insert(nonce, now + self.skew);
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        if self.seen.len() < 8192 {
            return;
        }
        self.seen.retain(|_, exp| *exp > now);
    }
}

/// Кэш идемпотентности: cmd_id → результат (TTL).
pub struct IdemCache {
    map: HashMap<u64, (String, u64)>,
    ttl: u64,
    cap: usize,
}

impl IdemCache {
    pub fn new() -> IdemCache {
        IdemCache {
            map: HashMap::new(),
            ttl: TIME_SKEW,
            cap: 4096,
        }
    }

    pub fn get(&mut self, cmd_id: u64) -> Option<String> {
        let now = now_unix();
        self.prune(now);
        match self.map.get(&cmd_id) {
            Some((blob, exp)) if *exp > now => Some(blob.clone()),
            _ => None,
        }
    }

    pub fn put(&mut self, cmd_id: u64, result: String) {
        let now = now_unix();
        self.prune(now);
        if self.map.len() >= self.cap {
            self.map.clear(); // простая политика: окно маленькое, безопасно
        }
        self.map.insert(cmd_id, (result, now + self.ttl));
    }

    fn prune(&mut self, now: u64) {
        if self.map.len() < self.cap {
            self.map.retain(|_, (_, exp)| *exp > now);
        }
    }
}

/// Свежий случайный cmd_id.
pub fn new_cmd_id() -> u64 {
    let mut id = random_u64();
    while id == 0 {
        id = random_u64();
    }
    id
}

/// Свежий случайный nonce.
pub fn new_nonce() -> u64 {
    random_u64()
}

/// Сгенерировать эфемерную пару X25519 для handshake.
pub fn ephemeral() -> (XSecret, XPub) {
    let s = XSecret::from(random_32());
    let p = XPub::from(&s);
    (s, p)
}

/// Декодировать b64 X25519 публичный ключ handshake.
pub fn x25519_pub(b64: &str) -> Result<XPub, String> {
    let raw = b64_decode(b64)?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "x25519 pub не 32 байта".to_string())?;
    Ok(XPub::from(arr))
}

pub fn x25519_pub_b64(p: &XPub) -> String {
    b64_encode(p.as_bytes())
}

/// Тихий генератор случайности для потоков (никогда не падает).
pub fn os_random_u64() -> u64 {
    OsRng.next_u64()
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(bytes: &[u8]) -> Vec<u8> {
        bytes[4..].to_vec()
    }

    #[test]
    fn plain_frame_roundtrip() {
        let f = Frame::plain(FT_HELLO, b"{\"v\":1}");
        let enc = encode_plain_frame(&f);
        assert_eq!(u32::from_be_bytes(enc[..4].try_into().unwrap()) as usize, enc.len() - 4);
        let body = body_of(&enc);
        let (ft, cmd_id, nonce, time, seq) = parse_header(&body).unwrap();
        assert_eq!(ft, FT_HELLO);
        assert_eq!((cmd_id, nonce, time, seq), (0, 0, 0, 0));
        assert_eq!(&body[33..], b"{\"v\":1}");
    }

    #[test]
    fn session_seal_open_roundtrip_both_sides() {
        let shared = random_32();
        let he = random_32();
        let ae = random_32();
        let (c2r, r2c) = derive_session(&shared, &he, &ae).unwrap();
        let client = Session::client_side(c2r, r2c);
        let relay = Session::relay_side(c2r, r2c);

        let wire = client.seal(FT_EXEC, 7, 9, b"hello exec");
        let body = body_of(&wire);
        let f = relay.open(&body).unwrap();
        assert_eq!(f.ft, FT_EXEC);
        assert_eq!(f.cmd_id, 7);
        assert_eq!(f.nonce, 9);
        assert_eq!(f.payload, b"hello exec");

        let back = relay.seal(FT_RESULT, 7, 10, b"result");
        let fr = client.open(&body_of(&back)).unwrap();
        assert_eq!(fr.ft, FT_RESULT);
        assert_eq!(fr.payload, b"result");
    }

    #[test]
    fn session_keys_are_directional() {
        let shared = random_32();
        let he = random_32();
        let ae = random_32();
        let (c2r, r2c) = derive_session(&shared, &he, &ae).unwrap();
        let client = Session::client_side(c2r, r2c);
        let wrong = Session::client_side(c2r, r2c);
        // клиент не может расшифровать собственный кадр (другое направление)
        let wire = client.seal(FT_PING, 0, 0, b"x");
        assert!(wrong.open(&body_of(&wire)).is_err());
    }

    #[test]
    fn session_rejects_replayed_seq() {
        let shared = random_32();
        let (c2r, r2c) = derive_session(&shared, &random_32(), &random_32()).unwrap();
        let client = Session::client_side(c2r, r2c);
        let relay = Session::relay_side(c2r, r2c);
        let wire = client.seal(FT_EXEC, 1, 1, b"first");
        let body = body_of(&wire);
        assert!(relay.open(&body).is_ok());
        // тот же кадр второй раз — seq не возрастает
        assert!(relay.open(&body).is_err());
    }

    #[test]
    fn session_rejects_tampered_ciphertext() {
        let shared = random_32();
        let (c2r, r2c) = derive_session(&shared, &random_32(), &random_32()).unwrap();
        let client = Session::client_side(c2r, r2c);
        let relay = Session::relay_side(c2r, r2c);
        let mut wire = client.seal(FT_EXEC, 1, 1, b"data");
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;
        assert!(relay.open(&body_of(&wire)).is_err());
    }

    #[test]
    fn session_seq_increments() {
        let shared = random_32();
        let (c2r, r2c) = derive_session(&shared, &random_32(), &random_32()).unwrap();
        let client = Session::client_side(c2r, r2c);
        let relay = Session::relay_side(c2r, r2c);
        for i in 0..5u64 {
            let wire = client.seal(FT_PING, 0, 0, b"p");
            let f = relay.open(&body_of(&wire)).unwrap();
            assert_eq!(f.seq, i + 1);
        }
    }

    #[test]
    fn replay_guard_time_window() {
        let mut g = ReplayGuard::new();
        let now = now_unix();
        assert!(g.check(now, 1).is_ok());
        assert!(g.check(now - 200, 2).is_ok()); // в окне
        assert!(g.check(now + 200, 3).is_ok()); // в окне
        assert!(g.check(now - 1000, 4).is_err()); // протухло
        assert!(g.check(now + 1000, 5).is_err()); // из будущего
    }

    #[test]
    fn replay_guard_rejects_duplicate_nonce() {
        let mut g = ReplayGuard::new();
        let now = now_unix();
        assert!(g.check(now, 42).is_ok());
        assert!(g.check(now, 42).is_err()); // replay
        assert!(g.check(now, 43).is_ok()); // другой nonce ок
    }

    #[test]
    fn idem_cache_roundtrip() {
        let mut c = IdemCache::new();
        assert!(c.get(1).is_none());
        c.put(1, "done".into());
        assert_eq!(c.get(1).unwrap(), "done");
        c.put(1, "replaced".into());
        assert_eq!(c.get(1).unwrap(), "replaced");
        assert!(c.get(2).is_none());
    }

    #[test]
    fn handshake_canonical_strings() {
        let h = Hello {
            v: 1,
            client_id: "main".into(),
            eph: "EPH".into(),
            time: 100,
            nonce: 200,
            sig: String::new(),
        };
        assert_eq!(hello_canonical(&h), "poler-wire-hello-v1|1|main|EPH|100|200");
        let a = HelloAck {
            v: 1,
            relay_id: "relay".into(),
            eph: "AEPH".into(),
            sig: String::new(),
        };
        assert_eq!(
            hello_ack_canonical(&a, "EPH"),
            "poler-wire-helloack-v1|1|relay|AEPH|EPH"
        );
    }

    #[test]
    fn frame_too_short_rejected() {
        assert!(parse_header(&[0u8; 10]).is_err());
    }

    #[test]
    fn cmd_id_never_zero() {
        for _ in 0..100 {
            assert_ne!(new_cmd_id(), 0);
        }
    }
}
