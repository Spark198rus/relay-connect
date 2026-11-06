"""
Перепись клиентского конфига Amnezia: меняем адрес сервера на RU-сервер.

Поддерживается:
  * vpn://...           — ключ Amnezia («Поделиться» → «Ключ Amnezia»)
  * .conf (WireGuard / AmneziaWG native) — строка Endpoint = host:port
"""

from __future__ import annotations

import base64
import json
import re
import struct
import zlib


class PatchError(Exception):
    pass


def _host_re(host: str) -> re.Pattern:
    return re.compile(r"(?<![\w.\-:])" + re.escape(host) + r"(?![\w.\-])")


# ----------------------------- vpn:// -------------------------------------- #

def decode_vpn(s: str) -> tuple[str, bool]:
    """-> (json-текст, был ли сжат qCompress)."""
    b = s.strip()
    if not b.startswith("vpn://"):
        raise PatchError("Ключ должен начинаться с vpn://")
    b = b[len("vpn://"):]
    try:
        data = base64.urlsafe_b64decode(b + "=" * (-len(b) % 4))
    except Exception:
        raise PatchError("Ключ vpn:// повреждён (base64)") from None
    try:
        # qCompress: 4 байта big-endian длины + zlib
        raw = zlib.decompress(data[4:])
        return raw.decode("utf-8"), True
    except zlib.error:
        try:
            return data.decode("utf-8"), False
        except UnicodeDecodeError:
            raise PatchError("Не удалось распаковать ключ vpn://") from None


def encode_vpn(text: str, compressed: bool = True) -> str:
    raw = text.encode("utf-8")
    data = struct.pack(">I", len(raw)) + zlib.compress(raw, 8) if compressed else raw
    return "vpn://" + base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def patch_vpn(key: str, new_host: str, old_host: str | None = None) -> tuple[str, str, int]:
    text, compressed = decode_vpn(key)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        raise PatchError("Внутри vpn:// не JSON — формат не распознан") from None
    old = old_host or obj.get("hostName")
    if not old:
        raise PatchError("В ключе не найден hostName — укажи старый адрес вручную")
    new_text, n = _host_re(old).subn(new_host, text)
    if n == 0:
        raise PatchError(f"Старый адрес {old} в ключе не найден")
    json.loads(new_text)  # sanity
    return encode_vpn(new_text, compressed), old, n


# ----------------------------- .conf --------------------------------------- #

_ENDPOINT = re.compile(r"^(\s*Endpoint\s*=\s*)(\[[^\]]+\]|[^:\s]+)(:\d+)\s*$", re.M | re.I)


def patch_conf(conf: str, new_host: str, old_host: str | None = None) -> tuple[str, str, int]:
    m = _ENDPOINT.search(conf)
    if not m:
        raise PatchError("В конфиге нет строки Endpoint = host:port")
    old = old_host or m.group(2).strip("[]")
    count = 0

    def repl(mm: re.Match) -> str:
        nonlocal count
        if mm.group(2).strip("[]") != old:
            return mm.group(0)
        count += 1
        return f"{mm.group(1)}{new_host}{mm.group(3)}"

    out = _ENDPOINT.sub(repl, conf)
    if count == 0:
        raise PatchError(f"Endpoint с адресом {old} не найден")
    return out, old, count


def patch_any(text: str, new_host: str, old_host: str | None = None) -> tuple[str, str, str, int]:
    """-> (результат, тип 'vpn'|'conf', старый адрес, число замен)."""
    t = text.strip()
    if t.startswith("vpn://"):
        res, old, n = patch_vpn(t, new_host, old_host)
        return res, "vpn", old, n
    res, old, n = patch_conf(text, new_host, old_host)
    return res, "conf", old, n
