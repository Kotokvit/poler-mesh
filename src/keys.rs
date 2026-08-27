//! # Ключи и конверты poler-wire v1
//!
//! Идентичность узла = пара `Ed25519` (подпись) + `X25519 static` (получение
//! запечатанных сообщений). Конверт [`SealedEnvelope`] — сквозное (E2E)
//! запечатывание «агент ⇄ клиент» поверх слепого релея: релей проверяет
//! только подпись над ШИФРОТЕКСТОМ и маршрутизирует, расшифровать не может.
//!
//! Формулы и канонические строки — см. `docs/wire.md` §4.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSecret};

// ---------------------------------------------------------------------------
// Случайность
// ---------------------------------------------------------------------------

/// 32 случайных байта из OsRng.
pub fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

/// 12 случайных байтов (AEAD nonce).
fn random_12() -> [u8; 12] {
    let mut b = [0u8; 12];
    OsRng.fill_bytes(&mut b);
    b
}

/// Случайный u64.
pub fn random_u64() -> u64 {
    OsRng.next_u64()
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// b64-хелперы
// ---------------------------------------------------------------------------

pub fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim()).map_err(|e| format!("b64: {e}"))
}

pub fn b64_32(s: &str) -> Result<[u8; 32], String> {
    let v = b64_decode(s)?;
    v.try_into().map_err(|_| "ожидалось 32 байта b64".into())
}

// ---------------------------------------------------------------------------
// Идентичность
// ---------------------------------------------------------------------------

/// Идентичность link-участника: Ed25519 (подписи) + X25519 static (запечатывание).
#[derive(Clone)]
pub struct Identity {
    pub signing: SigningKey,
    pub box_static: XSecret,
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    ed25519_seed: String,
    x25519_seed: String,
    created: String,
}

impl Identity {
    /// Сгенерировать новую идентичность.
    pub fn generate() -> Identity {
        Identity {
            signing: SigningKey::from_bytes(&random_32()),
            box_static: XSecret::from(random_32()),
        }
    }

    /// Публичный ключ подписи (Ed25519), b64 — регистрируют на релее/у агентов.
    pub fn verify_key_b64(&self) -> String {
        b64_encode(self.signing.verifying_key().as_bytes())
    }

    /// Публичный ключ запечатывания (X25519 static), b64 — выдают агентам.
    pub fn box_public_b64(&self) -> String {
        b64_encode(XPub::from(&self.box_static).as_bytes())
    }

    /// Сериализовать в JSON (секретные seed'ы! файл с правами 600).
    pub fn to_json(&self) -> String {
        let f = IdentityFile {
            ed25519_seed: b64_encode(self.signing.as_bytes()),
            x25519_seed: b64_encode(self.box_static.as_bytes()),
            created: format!("{}", now_unix()),
        };
        serde_json::to_string_pretty(&f).unwrap_or_default()
    }

    /// Прочитать из JSON-файла идентичности.
    pub fn from_json(s: &str) -> Result<Identity, String> {
        let f: IdentityFile =
            serde_json::from_str(s).map_err(|e| format!("identity json: {e}"))?;
        let seed = b64_32(&f.ed25519_seed)?;
        let xseed = b64_32(&f.x25519_seed)?;
        Ok(Identity {
            signing: SigningKey::from_bytes(&seed),
            box_static: XSecret::from(xseed),
        })
    }

    /// Подписать сообщение (Ed25519) → b64.
    pub fn sign_b64(&self, msg: &str) -> String {
        b64_encode(&self.signing.sign(msg.as_bytes()).to_bytes())
    }
}

/// Разобрать публичный Ed25519-ключ из b64.
pub fn verify_key_from_b64(s: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] = b64_32(s)?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("ed25519 pub: {e}"))
}

/// Разобрать публичный X25519-ключ из b64.
pub fn x25519_pub_from_b64(s: &str) -> Result<XPub, String> {
    Ok(XPub::from(b64_32(s)?))
}

/// Проверить Ed25519-подпись (b64) над сообщением.
pub fn verify_sig(vk: &VerifyingKey, msg: &str, sig_b64: &str) -> Result<(), String> {
    let raw = b64_decode(sig_b64)?;
    let sig = Signature::from_slice(&raw).map_err(|e| format!("sig: {e}"))?;
    vk.verify(msg.as_bytes(), &sig).map_err(|e| format!("подпись: {e}"))
}

// ---------------------------------------------------------------------------
// Конверты E2E (агент ⇄ клиент, сквозь слепой релей)
// ---------------------------------------------------------------------------

/// Запечатанный конверт (docs/wire.md §4). Подпись — над канонической строкой.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SealedEnvelope {
    pub v: u8,
    pub from: String,
    pub cmd_id: String,
    pub nonce: String,
    pub time: String,
    /// b64 X25519 эфемерный публичный ключ отправителя.
    pub eph: String,
    /// b64 12 байт AEAD nonce.
    pub n12: String,
    /// b64 шифротекст+tag.
    pub ct: String,
    /// b64 Ed25519 подпись отправителя.
    pub sig: String,
}

impl SealedEnvelope {
    pub fn cmd_id_u64(&self) -> Result<u64, String> {
        self.cmd_id.parse().map_err(|_| "cmd_id не u64".to_string())
    }
    pub fn nonce_u64(&self) -> Result<u64, String> {
        self.nonce.parse().map_err(|_| "nonce не u64".to_string())
    }
    pub fn time_u64(&self) -> Result<u64, String> {
        self.time.parse().map_err(|_| "time не u64".to_string())
    }
}

/// Каноническая подписываемая строка конверта.
pub fn envelope_canonical(e: &SealedEnvelope) -> String {
    format!(
        "poler-env-v1|{}|{}|{}|{}|{}|{}|{}|{}",
        e.v, e.from, e.cmd_id, e.nonce, e.time, e.eph, e.n12, e.ct
    )
}

/// AAD конверта — привязывает метаданные к шифротексту.
fn envelope_aad(from: &str, cmd_id: u64, nonce: u64) -> String {
    format!("poler-env-v1|{from}|{cmd_id}|{nonce}")
}

/// Ключ конверта: HKDF(X25519(eph, pub_получателя)).
fn envelope_key(shared: &[u8; 32], from: &str) -> Result<[u8; 32], String> {
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};
    let salt = Sha256::digest(format!("poler-env-v1|{from}").as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 32];
    hk.expand(b"poler-env", &mut okm)
        .map_err(|e| format!("hkdf: {e}"))?;
    Ok(okm)
}

fn aead_encrypt(key: &[u8; 32], n12: &[u8; 12], pt: &[u8], aad: &str) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    let c = ChaCha20Poly1305::new(key.into());
    c.encrypt(
        n12.into(),
        Payload {
            msg: pt,
            aad: aad.as_bytes(),
        },
    )
    .map_err(|_| "AEAD encrypt".to_string())
}

fn aead_decrypt(key: &[u8; 32], n12: &[u8; 12], ct: &[u8], aad: &str) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    let c = ChaCha20Poly1305::new(key.into());
    c.decrypt(
        n12.into(),
        Payload {
            msg: ct,
            aad: aad.as_bytes(),
        },
    )
    .map_err(|_| "AEAD decrypt: неверный ключ, повреждён шифротекст или AAD".to_string())
}

/// Эфемерная DH-пара отправителя: (секрет, публичный b64).
pub struct EphemeralPair {
    secret: XSecret,
    pub pub_b64: String,
}

impl EphemeralPair {
    pub fn generate() -> EphemeralPair {
        let secret = XSecret::from(random_32());
        let pub_b64 = b64_encode(XPub::from(&secret).as_bytes());
        EphemeralPair { secret, pub_b64 }
    }

    /// ECDH с публичным ключом получателя.
    pub fn shared_with(&self, recipient: &XPub) -> [u8; 32] {
        *self.secret.diffie_hellman(recipient).as_bytes()
    }

    /// ECDH с публичным ключом отправителя конверта (для открытия ответа).
    pub fn shared_with_sender(&self, sender_eph_b64: &str) -> Result<[u8; 32], String> {
        let peer = x25519_pub_from_b64(sender_eph_b64)?;
        Ok(*self.secret.diffie_hellman(&peer).as_bytes())
    }
}

/// Запечатать сообщение для получателя (его X25519 pub, b64).
/// Возвращает конверт и эфемерную пару (нужна для открытия ответа).
pub fn seal_envelope(
    from: &str,
    recipient_box_pub_b64: &str,
    cmd_id: u64,
    nonce: u64,
    plaintext: &str,
    signer: &SigningKey,
) -> Result<(SealedEnvelope, EphemeralPair), String> {
    let recipient = x25519_pub_from_b64(recipient_box_pub_b64)?;
    let eph = EphemeralPair::generate();
    let shared = eph.shared_with(&recipient);
    let key = envelope_key(&shared, from)?;
    let n12 = random_12();
    let time = now_unix();
    let aad = envelope_aad(from, cmd_id, nonce);
    let ct = aead_encrypt(&key, &n12, plaintext.as_bytes(), &aad)?;
    let env = SealedEnvelope {
        v: 1,
        from: from.to_string(),
        cmd_id: cmd_id.to_string(),
        nonce: nonce.to_string(),
        time: time.to_string(),
        eph: eph.pub_b64.clone(),
        n12: b64_encode(&n12),
        ct: b64_encode(&ct),
        sig: String::new(),
    };
    let canonical = envelope_canonical(&env);
    let sig = signer.sign(canonical.as_bytes());
    let mut env = env;
    env.sig = b64_encode(&sig.to_bytes());
    Ok((env, eph))
}

/// Открыть конверт: проверить подпись отправителя и расшифровать своим
/// X25519 static. Возвращает открытый текст.
pub fn open_envelope(
    env: &SealedEnvelope,
    my_box_static: &XSecret,
    sender_verify: &VerifyingKey,
) -> Result<String, String> {
    // 1. подпись отправителя над канонической строкой
    verify_sig(sender_verify, &envelope_canonical(env), &env.sig)?;
    // 2. ECDH: мой static × эфемерный ключ отправителя
    let sender_eph = x25519_pub_from_b64(&env.eph)?;
    let shared = *my_box_static.diffie_hellman(&sender_eph).as_bytes();
    let key = envelope_key(&shared, &env.from)?;
    // 3. расшифровка с привязкой метаданных
    let n12_raw = b64_decode(&env.n12)?;
    let n12: [u8; 12] = n12_raw
        .try_into()
        .map_err(|_| "n12 не 12 байт".to_string())?;
    let ct = b64_decode(&env.ct)?;
    let aad = envelope_aad(&env.from, env.cmd_id_u64()?, env.nonce_u64()?);
    let pt = aead_decrypt(&key, &n12, &ct, &aad)?;
    String::from_utf8(pt).map_err(|_| "utf8".to_string())
}

/// Открыть конверт СВОЕЙ эфемерной парой (сторона агента открывает ответ).
pub fn open_envelope_ephemeral(
    env: &SealedEnvelope,
    my_eph: &EphemeralPair,
    sender_verify: &VerifyingKey,
) -> Result<String, String> {
    verify_sig(sender_verify, &envelope_canonical(env), &env.sig)?;
    let shared = my_eph.shared_with_sender(&env.eph)?;
    let key = envelope_key(&shared, &env.from)?;
    let n12_raw = b64_decode(&env.n12)?;
    let n12: [u8; 12] = n12_raw
        .try_into()
        .map_err(|_| "n12 не 12 байт".to_string())?;
    let ct = b64_decode(&env.ct)?;
    let aad = envelope_aad(&env.from, env.cmd_id_u64()?, env.nonce_u64()?);
    let pt = aead_decrypt(&key, &n12, &ct, &aad)?;
    String::from_utf8(pt).map_err(|_| "utf8".to_string())
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        let data = random_32();
        assert_eq!(b64_32(&b64_encode(&data)).unwrap(), data);
        assert!(b64_32("not!!b64").is_err());
    }

    #[test]
    fn identity_json_roundtrip_and_pubs() {
        let id = Identity::generate();
        let json = id.to_json();
        let back = Identity::from_json(&json).unwrap();
        assert_eq!(id.verify_key_b64(), back.verify_key_b64());
        assert_eq!(id.box_public_b64(), back.box_public_b64());
        assert_eq!(id.sign_b64("msg"), back.sign_b64("msg"));
    }

    #[test]
    fn identity_from_bad_json_fails() {
        assert!(Identity::from_json("{}").is_err());
        assert!(Identity::from_json("not json").is_err());
    }

    #[test]
    fn verify_key_from_b64_rejects_garbage() {
        assert!(verify_key_from_b64("AAAA").is_err()); // не 32 байта
        assert!(verify_key_from_b64("not!!b64").is_err());
        // валидный ключ — только сгенерированная пара (случайные 32 байта
        // дают валидную точку кривой лишь в ~50% случаев — не детерминизм)
        let id = Identity::generate();
        assert!(verify_key_from_b64(&id.verify_key_b64()).is_ok());
    }

    #[test]
    fn envelope_seal_open_roundtrip() {
        let client = Identity::generate();
        let agent = Identity::generate();
        let mcp = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

        let (env, _eph) = seal_envelope(
            "glm",
            &client.box_public_b64(),
            42,
            777,
            mcp,
            &agent.signing,
        )
        .unwrap();

        let opened =
            open_envelope(&env, &client.box_static, &agent.signing.verifying_key()).unwrap();
        assert_eq!(opened, mcp);
        assert_eq!(env.cmd_id_u64().unwrap(), 42);
        assert_eq!(env.nonce_u64().unwrap(), 777);
    }

    #[test]
    fn envelope_open_by_ephemeral_side() {
        // агент запечатал → клиент открыл static'ом → клиент запечатал ответ
        // на eph агента → агент открыл своей эфемерной парой
        let client = Identity::generate();
        let agent = Identity::generate();
        let (env, agent_eph) = seal_envelope(
            "glm",
            &client.box_public_b64(),
            1,
            2,
            "ping",
            &agent.signing,
        )
        .unwrap();

        let opened =
            open_envelope(&env, &client.box_static, &agent.signing.verifying_key()).unwrap();
        assert_eq!(opened, "ping");

        // ответ клиента: запечатан на eph агента, подписан клиентом
        let (resp, _client_eph) = seal_envelope(
            "main",
            &env.eph,
            1,
            3,
            "pong",
            &client.signing,
        )
        .unwrap();
        let back = open_envelope_ephemeral(
            &resp,
            &agent_eph,
            &client.signing.verifying_key(),
        )
        .unwrap();
        assert_eq!(back, "pong");
    }

    #[test]
    fn envelope_tampered_ciphertext_fails() {
        let client = Identity::generate();
        let agent = Identity::generate();
        let (mut env, _) = seal_envelope(
            "glm",
            &client.box_public_b64(),
            1,
            2,
            "secret",
            &agent.signing,
        )
        .unwrap();
        // подменили шифротекст → ломается и подпись, и AEAD
        let ct = b64_decode(&env.ct).unwrap();
        let mut bad = ct.clone();
        bad[0] ^= 0xFF;
        env.ct = b64_encode(&bad);
        assert!(open_envelope(&env, &client.box_static, &agent.signing.verifying_key()).is_err());
    }

    #[test]
    fn envelope_wrong_signer_fails() {
        let client = Identity::generate();
        let agent = Identity::generate();
        let stranger = Identity::generate();
        let (env, _) = seal_envelope(
            "glm",
            &client.box_public_b64(),
            1,
            2,
            "secret",
            &stranger.signing, // подписал чужой
        )
        .unwrap();
        assert!(open_envelope(&env, &client.box_static, &agent.signing.verifying_key()).is_err());
    }

    #[test]
    fn envelope_wrong_recipient_fails() {
        let client = Identity::generate();
        let other = Identity::generate();
        let agent = Identity::generate();
        let (env, _) = seal_envelope(
            "glm",
            &other.box_public_b64(), // запечатано НЕ клиенту
            1,
            2,
            "secret",
            &agent.signing,
        )
        .unwrap();
        assert!(open_envelope(&env, &client.box_static, &agent.signing.verifying_key()).is_err());
    }

    #[test]
    fn envelope_metadata_binding() {
        // AAD привязывает cmd_id/nonce: расшифровка с другим cmd_id невозможна
        let client = Identity::generate();
        let agent = Identity::generate();
        let (mut env, _) = seal_envelope(
            "glm",
            &client.box_public_b64(),
            111,
            222,
            "secret",
            &agent.signing,
        )
        .unwrap();
        env.cmd_id = "999".to_string();
        env.sig = agent.sign_b64(&envelope_canonical(&env)); // перевалидная подпись
        assert!(open_envelope(&env, &client.box_static, &agent.signing.verifying_key()).is_err());
    }

    #[test]
    fn canonical_string_is_stable() {
        let env = SealedEnvelope {
            v: 1,
            from: "glm".into(),
            cmd_id: "42".into(),
            nonce: "7".into(),
            time: "99".into(),
            eph: "EPH".into(),
            n12: "N12".into(),
            ct: "CT".into(),
            sig: String::new(),
        };
        assert_eq!(
            envelope_canonical(&env),
            "poler-env-v1|1|glm|42|7|99|EPH|N12|CT"
        );
    }
}
