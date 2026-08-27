#!/usr/bin/env python3
"""poler_agent.py — агентский клиент POLER Mesh (sealed-режим, docs/wire.md §4).

Запечатывает MCP-запросы для X25519-static ключа link-клиента, подписывает
Ed25519 и отправляет на poler-relay POST /mcp-sealed. Релей видит только
шифротекст. Ответ расшифровывается эфемерным ключом и проверяется подписью
клиента.

Требования: python3, пакет `cryptography` (pip install cryptography).

Быстрый старт:
    # 1) один раз: сгенерировать ключ агента и отдать владельцу verify_key
    python3 poler_agent.py init

    # 2) владелец вносит verify_key в [[agents]] relay.toml и выдаёт вам:
    #    box_key (X25519) и verify_key (Ed25519) КЛИЕНТА

    # 3) вызовы (examples):
    python3 poler_agent.py call --relay http://VPS:8770 \\
        --client-box B64 --client-verify B64 \\
        '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

    python3 poler_agent.py tools --relay http://VPS:8770 \\
        --client-box B64 --client-verify B64

    python3 poler_agent.py call --relay http://VPS:8770 \\
        --client-box B64 --client-verify B64 \\
        --tool poler_gmail --args '{"query":"is:unread"}'
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.request

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption)
except ImportError:
    print("нужен пакет cryptography: pip install cryptography", file=sys.stderr)
    sys.exit(2)

IDENTITY_PATH = os.path.join(os.path.expanduser("~"), ".poler-agent.json")
ENV_V1 = "poler-env-v1"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


def canonical(env: dict) -> str:
    return "|".join([
        ENV_V1, str(env["v"]), env["from"], env["cmd_id"], env["nonce"],
        env["time"], env["eph"], env["n12"], env["ct"],
    ])


def aad(from_id: str, cmd_id: int, nonce: int) -> str:
    return f"{ENV_V1}|{from_id}|{cmd_id}|{nonce}"


def envelope_key(shared: bytes, from_id: str) -> bytes:
    salt = hashlib.sha256(f"{ENV_V1}|{from_id}".encode()).digest()
    # HKDF-SHA256 (RFC 5869), info="poler-env"
    prk = hmac.new(salt, shared, hashlib.sha256).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < 32:
        t = hmac.new(prk, t + b"poler-env" + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:32])


def load_identity() -> dict:
    if not os.path.exists(IDENTITY_PATH):
        print(f"нет {IDENTITY_PATH} — сначала: poler_agent.py init", file=sys.stderr)
        sys.exit(2)
    with open(IDENTITY_PATH) as f:
        return json.load(f)


def save_identity() -> None:
    if os.path.exists(IDENTITY_PATH):
        print(f"{IDENTITY_PATH} уже существует — не трогаю", file=sys.stderr)
        sys.exit(1)
    ed = Ed25519PrivateKey.generate()
    data = {
        "ed25519_seed": b64(ed.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        "created": int(time.time()),
    }
    with open(IDENTITY_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(IDENTITY_PATH, 0o600)
    pub = ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(f"создан {IDENTITY_PATH}")
    print()
    print("Отдай владельцу эту строку (в [[agents]] relay.toml, id по договорённости):")
    print(f'  verify_key = "{b64(pub)}"')


def seal(mcp_json: str, agent_id: str, ident: dict,
         client_box_b64: str, client_verify_b64: str):
    """Запечатать запрос. Возвращает (envelope, eph_secret, client_vk)."""
    seed = unb64(ident["ed25519_seed"])
    signing = Ed25519PrivateKey.from_private_bytes(seed)
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    client_box = X25519PublicKey.from_public_bytes(unb64(client_box_b64))
    shared = eph.exchange(client_box)
    key = envelope_key(shared, agent_id)
    cmd_id = secrets.randbits(63) | 1
    nonce = secrets.randbits(63) | 1
    now = int(time.time())
    n12 = secrets.token_bytes(12)
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(n12, mcp_json.encode(),
                      aad(agent_id, cmd_id, nonce).encode())
    env = {
        "v": 1, "from": agent_id, "cmd_id": str(cmd_id),
        "nonce": str(nonce), "time": str(now),
        "eph": b64(eph_pub), "n12": b64(n12), "ct": b64(ct), "sig": "",
    }
    env["sig"] = b64(signing.sign(canonical(env).encode()))
    client_vk = Ed25519PublicKey.from_public_bytes(unb64(client_verify_b64))
    return env, eph, client_vk


def open_response(env: dict, eph, client_vk) -> str:
    """Расшифровать ответ-конверт клиента своей эфемерной парой."""
    client_vk.verify(unb64(env["sig"]), canonical(env).encode())
    sender_eph = X25519PublicKey.from_public_bytes(unb64(env["eph"]))
    shared = eph.exchange(sender_eph)
    key = envelope_key(shared, env["from"])
    aead = ChaCha20Poly1305(key)
    cmd_id = int(env["cmd_id"]); nonce = int(env["nonce"])
    pt = aead.decrypt(unb64(env["n12"]), unb64(env["ct"]),
                      aad(env["from"], cmd_id, nonce).encode())
    return pt.decode()


def post_sealed(relay: str, env: dict, timeout: int = 180) -> dict:
    url = relay.rstrip("/") + "/mcp-sealed"
    data = json.dumps(env).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def build_mcp(args) -> str:
    if args.mcp:
        return args.mcp
    if args.tool:
        call = {
            "jsonrpc": "2.0", "id": args.id,
            "method": "tools/call",
            "params": {"name": args.tool,
                       "arguments": json.loads(args.args or "{}")},
        }
        return json.dumps(call)
    return json.dumps({"jsonrpc": "2.0", "id": args.id, "method": "tools/list"})


def cmd_call(args) -> None:
    ident = load_identity()
    mcp = build_mcp(args)
    env, eph, client_vk = seal(mcp, args.agent_id, ident,
                               args.client_box, args.client_verify)
    resp_env = post_sealed(args.relay, env, args.timeout)
    opened = open_response(resp_env, eph, client_vk)
    try:
        print(json.dumps(json.loads(opened), indent=2, ensure_ascii=False))
    except json.JSONDecodeError:
        print(opened)


def cmd_health(args) -> None:
    url = args.relay.rstrip("/") + "/health"
    with urllib.request.urlopen(url, timeout=15) as resp:
        print(resp.read().decode())


def cmd_tools(args) -> None:
    args.tool = None
    args.args = None
    args.mcp = None
    cmd_call(args)


def main() -> None:
    p = argparse.ArgumentParser(description="Агент POLER Mesh (sealed, docs/wire.md)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="сгенерировать ключ агента")

    c = sub.add_parser("call", help="отправить MCP-запрос (sealed)")
    c.add_argument("--relay", required=True, help="http://host:port релея")
    c.add_argument("--client-box", required=True, help="X25519 pub клиента (b64)")
    c.add_argument("--client-verify", required=True, help="Ed25519 pub клиента (b64)")
    c.add_argument("--agent-id", default=os.environ.get("POLER_AGENT_ID", "glm"))
    c.add_argument("--mcp", help="готовый MCP JSON-RPC запрос")
    c.add_argument("--tool", help="tools/call: имя инструмента")
    c.add_argument("--args", help="arguments для --tool (JSON)")
    c.add_argument("--id", type=int, default=1)
    c.add_argument("--timeout", type=int, default=180)
    c.set_defaults(func=cmd_call)

    t = sub.add_parser("tools", help="tools/list (sealed)")
    for flag, help_ in [("--relay", "http://host:port релея"),
                        ("--client-box", "X25519 pub клиента (b64)"),
                        ("--client-verify", "Ed25519 pub клиента (b64)")]:
        t.add_argument(flag, required=True, help=help_)
    t.add_argument("--agent-id", default=os.environ.get("POLER_AGENT_ID", "glm"))
    t.add_argument("--id", type=int, default=1)
    t.add_argument("--timeout", type=int, default=180)
    t.set_defaults(func=cmd_tools)

    h = sub.add_parser("health", help="GET /health релея")
    h.add_argument("--relay", required=True)
    h.set_defaults(func=cmd_health)

    args = p.parse_args()
    if args.cmd == "init":
        save_identity()
        return
    args.func(args)


if __name__ == "__main__":
    main()
