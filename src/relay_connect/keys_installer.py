"""
Ключи для AmneziaWG, поставленного amneziawg-installer.

Клиентов создаёт сам amneziawg-installer: программа запускает на зарубежном сервере
`manage_amneziawg.sh add <имя>` и забирает готовые файлы из /root/awg:
  <имя>.conf    — конфиг для приложения AmneziaWG;
  <имя>.vpnuri  — та же настройка ссылкой vpn:// для приложения Amnezia VPN
                  (создаётся, если на сервере есть perl с Compress::Zlib).

Адрес RU-сервера попадает в ключи через AWG_ENDPOINT (см. relay_core.point_clients_to_relay):
установщик сам пишет его в Endpoint и исключает из AllowedIPs, поэтому конфиги после него не правим.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from . import relay_core as core
from .config_patch import PatchError, patch_conf, patch_vpn

NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,63}")   # validate_client_name в manage_amneziawg.sh
TRANSLIT = dict(zip(
    "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
    ["a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p", "r", "s", "t",
     "u", "f", "h", "ts", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya"]))


@dataclass
class UserKey:
    name: str
    ip: str
    conf: str          # конфиг AmneziaWG (.conf)
    vpn: str | None    # ссылка vpn:// для Amnezia VPN; None, если установщик её не создал


def client_name(raw: str) -> str:
    """Имя в том виде, который принимает установщик: латиница, цифры, «-» и «_», до 63 символов.

    Кириллицу транслитерируем, пробелы и прочие знаки заменяем на «_».
    """
    out = []
    for ch in raw.strip():
        low = ch.lower()
        if low in TRANSLIT:
            t = TRANSLIT[low]
            out.append(t.capitalize() if ch != low else t)
        elif re.fullmatch(r"[A-Za-z0-9_-]", ch):
            out.append(ch)
        else:
            out.append("_")
    name = re.sub(r"_+", "_", "".join(out)).strip("_")[:63]
    if not NAME_RE.fullmatch(name):
        raise core.RelayError("Впиши имя клиента: латиница, цифры, «-» и «_», например phone_mom")
    return name


def _endpoint_host(conf: str) -> str:
    m = re.search(r"^\s*Endpoint\s*=\s*(\[[^\]]+\]|[^:\s]+)", conf, re.M)
    return m.group(1).strip("[]") if m else ""


def _read_key(de: core.Remote, name: str, ru_ip: str, log: core.Log) -> UserKey:
    base = f"{core.AWG_DIR}/{name}"
    code, conf, _ = de.run(f"cat {shlex.quote(base + '.conf')}")
    if code != 0 or "[Interface]" not in conf:
        raise core.RelayError(f"Нет файла {base}.conf. Перевыпусти его на зарубежном сервере: "
                              f"`bash {core.AWG_MANAGE} regen {name}`")
    code, vpn, _ = de.run(f"cat {shlex.quote(base + '.vpnuri')} 2>/dev/null")
    vpn = vpn.strip() if code == 0 and vpn.strip().startswith("vpn://") else None

    host = _endpoint_host(conf)
    if host != ru_ip:
        # сюда попадаем, только если regen не сработал; меняем адрес сами, чтобы ключ всё же вёл на relay
        log(f"В файле {base}.conf адрес {host or '?'}, а не {ru_ip} — меняю его в выданном ключе. "
            f"Файл на сервере стоит перевыпустить: `bash {core.AWG_MANAGE} regen {name}`", "warn")
        try:
            conf = patch_conf(conf, ru_ip, host or None)[0]
            vpn = patch_vpn(vpn, ru_ip)[0] if vpn else None
        except PatchError as e:
            raise core.RelayError(f"Не удалось поменять адрес в ключе {name}: {e}") from None

    m = re.search(r"^\s*Address\s*=\s*([0-9.]+)", conf, re.M)
    if not vpn:
        log("Ссылку vpn:// установщик не создал (на сервере нет perl с Compress::Zlib) — есть только .conf "
            "для приложения AmneziaWG", "warn")
    return UserKey(name=name, ip=m.group(1) if m else "?", conf=conf, vpn=vpn)


def _server(ru: core.Remote, de: core.Remote, ru_ip: str, log: core.Log) -> core.AwgServer:
    log("Читаю настройки AmneziaWG на зарубежном сервере…", "step")
    srv = core.find_awg(de, log)
    if not any(port == srv.port and '"realm"' in line for _, port, line in core.listeners(ru, "udp")):
        log(f"RU-сервер не пересылает порт {srv.port}/udp — ключ не заработает, пока не нажмёшь «Настроить»",
            "warn")
    core.point_clients_to_relay(de, srv, ru_ip, log)
    return srv


def create_user_key(ru: core.Remote, de: core.Remote, ru_ip: str, raw_name: str, log: core.Log) -> UserKey:
    name = client_name(raw_name)
    srv = _server(ru, de, ru_ip, log)
    if name in srv.clients:
        raise core.RelayError(f"Клиент «{name}» уже есть. Впиши другое имя или нажми «Показать ключ существующего», "
                              "чтобы получить его ключ.")
    log(f"Создаю клиента «{name}» (manage_amneziawg.sh add)…", "step")
    res = core.awg_manage(de, f"add {shlex.quote(name)}", timeout=300)
    entry = next((r for r in res.get("results", []) if r.get("name") == name), {})
    if entry.get("status") != "created":
        raise core.RelayError(f"Установщик не создал клиента «{name}» (статус: {entry.get('status') or '?'}, "
                              f"{res.get('error') or 'подробности: bash ' + core.AWG_MANAGE + ' add ' + name})")
    if not res.get("applied"):
        log(f"Клиент записан в конфиг, но AmneziaWG не применил его на лету. На зарубежном сервере: "
            f"`systemctl status {core.AWG_UNIT}`", "warn")
    key = _read_key(de, name, ru_ip, log)
    log(f"Клиент «{name}» создан, адрес в туннеле {key.ip}. Ключ ведёт на RU-сервер {ru_ip}:{srv.port}", "ok")
    return key


def get_user_key(ru: core.Remote, de: core.Remote, ru_ip: str, raw_name: str, log: core.Log) -> UserKey:
    """Ключ уже существующего клиента (например, после перевыпуска с адресом RU-сервера)."""
    name = client_name(raw_name)
    srv = _server(ru, de, ru_ip, log)
    if name not in srv.clients:
        known = ", ".join(srv.clients) or "клиентов пока нет"
        raise core.RelayError(f"Клиента «{name}» на сервере нет. Есть: {known}")
    key = _read_key(de, name, ru_ip, log)
    log(f"Ключ клиента «{name}» ({key.ip}) ведёт на RU-сервер {ru_ip}:{srv.port}", "ok")
    return key
