"""
Выдача ключей AmneziaWG через relay — без управления сервером из приложения Amnezia.

Обычный ключ: добавляем нового пользователя прямо в AmneziaWG на зарубежном сервере
(так же, как это делает приложение Amnezia) и собираем клиентский конфиг с Endpoint = RU-сервер.

Админский ключ («полный доступ»): JSON сервера с SSH-доступом, как его экспортирует Amnezia
(ExportController::generateFullAccessConfig). hostName = IPv4 RU-сервера, port = порт SSH-проброса
на RU-сервере → приложение управляет сервером через relay, и все ключи, которые оно создаёт
через «Поделиться», сразу получаются с адресом RU-сервера.

Формат и пути взяты из исходников amnezia-client (master, ноябрь 2026):
  контейнер amnezia-awg2: /opt/amnezia/awg/awg0.conf, утилиты awg/awg-quick, интерфейс awg0;
  контейнер amnezia-awg (старый): /opt/amnezia/awg/wg0.conf, wg/wg-quick, wg0;
  ключи: /opt/amnezia/awg/wireguard_server_public_key.key, wireguard_psk.key (PSK общий для всех);
  имена пользователей: /opt/amnezia/awg/clientsTable — JSON-массив
  [{"clientId": <pubkey>, "userData": {"clientName": ..., "creationDate": ...}}].
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import shlex
import time
from dataclasses import dataclass, field

from . import relay_core as core
from .config_patch import encode_vpn

AWG_DIR = "/opt/amnezia/awg"
CONTAINERS = ("amnezia-awg2", "amnezia-awg")          # в порядке предпочтения
VARIANTS = (                                          # (конфиг сервера, утилита, интерфейс)
    (f"{AWG_DIR}/awg0.conf", "awg", "awg0"),
    (f"{AWG_DIR}/wg0.conf", "wg", "wg0"),
)
JUNK_REQUIRED = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")   # без них Amnezia не примет AWG
JUNK_ORDER = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
SPECIAL = ("I1", "I2", "I3", "I4", "I5")
AMNEZIA_DNS = "172.29.172.254"   # адрес контейнера amnezia-dns внутри туннеля
# Строки [Interface] сервера, которые клиенту не нужны. Всё остальное (Jc…H4, S3/S4 и новые параметры
# AmneziaWG 3.x: HeaderProtectionKey, ContentPaddingAddition, Rekey*, RandomTrailers…) копируется клиенту как есть.
SERVER_ONLY = {"PrivateKey", "Address", "ListenPort", "PostUp", "PostDown", "PreUp", "PreDown",
               "SaveConfig", "Table", "FwMark", "MTU", "DNS"}
# Параметры, по которым видно AmneziaWG 3.x (в ключе Amnezia тогда protocol_version = "3.1")
AWG3_MARKERS = {"HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
                "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"}
CLIENT_MTU = "1280"   # как в ключах, которые выдаёт приложение Amnezia


@dataclass
class AwgServer:
    container: str
    conf_path: str
    tool: str
    iface: str
    interface: dict[str, str]
    special: dict[str, str]
    peer_ips: list[str]
    server_pub: str
    psk: str
    dns1: str
    other_containers: list[str] = field(default_factory=list)

    @property
    def listen_port(self) -> int:
        try:
            return int(self.interface["ListenPort"])
        except (KeyError, ValueError):
            raise core.RelayError(f"В {self.conf_path} нет ListenPort — конфиг AmneziaWG выглядит необычно") from None

    @property
    def network(self) -> ipaddress.IPv4Network:
        addr = self.interface.get("Address", "10.8.1.0/24").split(",")[0].strip()
        return ipaddress.ip_interface(addr).network

    def in_container(self, cmd: str) -> str:
        return f"docker exec {self.container} bash -c {shlex.quote(cmd)}"

    @property
    def client_params(self) -> dict[str, str]:
        """Параметры обфускации для клиента: сначала классические Jc…H4, потом остальные в порядке конфига."""
        params = {k: self.interface[k] for k in JUNK_ORDER if k in self.interface}
        for k, v in self.interface.items():
            if k not in SERVER_ONLY and k not in params and k not in SPECIAL:
                params[k] = v
        return params

    @property
    def protocol_version(self) -> str | None:
        if AWG3_MARKERS & self.interface.keys():
            return "3.1"
        if "S3" in self.interface and "S4" in self.interface:
            return "2"
        return None

    @property
    def keepalive(self) -> str:
        # AmneziaWG 3.x понимает интервал «25-35», старые версии — только число
        return "25-35" if (self.protocol_version or "").startswith("3") else "25"

    def awg_block(self) -> dict:
        """Объект "awg" контейнера в формате ключа Amnezia (без last_config)."""
        awg: dict = dict(self.client_params)
        awg.update({k: self.special.get(k, "") for k in SPECIAL})
        awg.update({
            "port": str(self.listen_port),
            "subnet_address": str(self.network.network_address),
            "subnet_cidr": str(self.network.prefixlen),
            "transport_proto": "udp",
        })
        if self.protocol_version:
            awg["protocol_version"] = self.protocol_version
        return awg


@dataclass
class UserKey:
    name: str
    ip: str
    conf: str   # нативный конфиг AmneziaWG (.conf)
    vpn: str    # тот же конфиг одной строкой vpn:// — удобно пересылать в мессенджере


# --------------------------------------------------------------------------- #

def _parse_conf(text: str) -> tuple[dict[str, str], dict[str, str], list[str]]:
    interface: dict[str, str] = {}
    special: dict[str, str] = {}
    peer_ips: list[str] = []
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.lower()
            continue
        commented = line.startswith("#")
        body = line.lstrip("#").strip()
        if "=" not in body:
            continue
        key, value = (s.strip() for s in body.split("=", 1))
        if section == "[interface]":
            if key in SPECIAL:
                # I1..I5 в серверном конфиге закомментированы, но это значения, которые Amnezia кладёт клиентам
                if value and not value.startswith("$"):
                    special[key] = value
            elif not commented:
                interface[key] = value
        elif section == "[peer]" and not commented and key == "AllowedIPs":
            for part in value.split(","):
                m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)", part)
                if m:
                    peer_ips.append(m.group(1))
    return interface, special, peer_ips


def find_awg(de: core.Remote, log: core.Log) -> AwgServer:
    _, out, _ = de.run("docker ps --format '{{.Names}}'")
    names = out.split()
    found = [c for c in CONTAINERS if c in names]
    if not found:
        raise core.RelayError("На зарубежном сервере не запущен контейнер AmneziaWG (amnezia-awg2 или amnezia-awg). "
                              "Ключи умеет выдавать только для протокола AmneziaWG.")
    container = found[0]
    if len(found) > 1:
        log(f"Найдено два контейнера AmneziaWG, беру {container}", "warn")

    for conf_path, tool, iface in VARIANTS:
        if de.ok(f"docker exec {container} test -f {conf_path}"):
            break
    else:
        raise core.RelayError(f"В контейнере {container} нет конфига {AWG_DIR}/awg0.conf или wg0.conf")

    _, text, _ = de.run(f"docker exec {container} cat {conf_path}", check=True)
    interface, special, peer_ips = _parse_conf(text)
    missing = [k for k in JUNK_REQUIRED if k not in interface]
    if missing:
        log(f"В конфиге сервера нет параметров {', '.join(missing)} — ключ может импортироваться как обычный WireGuard",
            "warn")

    code, pub, _ = de.run(f"docker exec {container} cat {AWG_DIR}/wireguard_server_public_key.key")
    if code != 0 or not pub.strip():
        _, pub, _ = de.run(f"docker exec {container} bash -c {shlex.quote(f'{tool} show {iface} public-key')}")
    if not pub.strip():
        raise core.RelayError("Не удалось прочитать публичный ключ сервера AmneziaWG")
    _, psk, _ = de.run(f"docker exec {container} cat {AWG_DIR}/wireguard_psk.key")

    srv = AwgServer(
        container=container, conf_path=conf_path, tool=tool, iface=iface,
        interface=interface, special=special, peer_ips=peer_ips,
        server_pub=pub.strip(), psk=psk.strip(),
        dns1=AMNEZIA_DNS if "amnezia-dns" in names else "1.1.1.1",
        other_containers=[n for n in names if n.startswith("amnezia-") and n not in CONTAINERS + ("amnezia-dns",)],
    )
    log(f"AmneziaWG {srv.protocol_version or '1.x'}: контейнер {container}, порт {srv.listen_port}/udp, "
        f"пользователей {len(peer_ips)}", "ok")
    log("Параметры протокола: " + ", ".join(srv.client_params), "info")
    return srv


def _next_ip(srv: AwgServer) -> str:
    """Как в Amnezia: последний AllowedIPs + 1, пропуская .0/.255 и занятые адреса."""
    net = srv.network
    used = {ipaddress.ip_address(x) for x in srv.peer_ips}
    used.add(ipaddress.ip_interface(srv.interface.get("Address", "10.8.1.0/24").split(",")[0].strip()).ip)
    cand = (ipaddress.ip_address(srv.peer_ips[-1]) if srv.peer_ips else net.network_address) + 1
    for _ in range(net.num_addresses):
        if cand not in net or cand == net.broadcast_address:
            cand = net.network_address + 1
        if cand not in used and int(cand) & 0xFF not in (0, 255):
            return str(cand)
        cand += 1
    raise core.RelayError(f"В подсети AmneziaWG {net} не осталось свободных адресов")


def _qt_date() -> str:
    """Формат QDateTime::toString() по умолчанию, как пишет Amnezia: «Fri Nov 6 15:04:05 2026»."""
    t = time.localtime()
    days = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return f"{days[t.tm_wday]} {months[t.tm_mon - 1]} {t.tm_mday} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} {t.tm_year}"


def _pipe(data: str) -> str:
    """`echo <base64> | base64 -d` — передать текст на сервер без проблем с кавычками."""
    return f"echo {base64.b64encode(data.encode()).decode()} | base64 -d"


def _apply(de: core.Remote, srv: AwgServer) -> bool:
    cmd = (f"{srv.tool}-quick strip {srv.conf_path} > /dev/null && "
           f"{srv.tool} syncconf {srv.iface} <({srv.tool}-quick strip {srv.conf_path})")
    return de.ok(srv.in_container(cmd), timeout=60)


def _add_client_name(de: core.Remote, srv: AwgServer, pub: str, name: str, log: core.Log):
    path = f"{AWG_DIR}/clientsTable"
    code, out, _ = de.run(f"docker exec {srv.container} cat {path}")
    if code != 0 or not out.strip():
        table: list = []
    else:
        try:
            table = json.loads(out)
        except json.JSONDecodeError:
            log("clientsTable не читается — имя пользователя в приложении Amnezia не появится", "warn")
            return
    if not isinstance(table, list):
        log("clientsTable в старом формате — имя пользователя в приложении Amnezia не появится", "warn")
        return
    table.append({"clientId": pub, "userData": {"clientName": name, "creationDate": _qt_date()}})
    text = json.dumps(table, ensure_ascii=False, indent=4)
    if not de.ok(f"{_pipe(text)} | docker exec -i {srv.container} sh -c 'cat > {path}'"):
        log("Не удалось записать имя пользователя в clientsTable", "warn")


def _client_conf(srv: AwgServer, ip: str, priv: str, endpoint_host: str, dns_placeholders: bool = False) -> str:
    """Нативный конфиг клиента. dns_placeholders=True — как в last_config ключа Amnezia ($PRIMARY_DNS…)."""
    dns = "$PRIMARY_DNS, $SECONDARY_DNS" if dns_placeholders else f"{srv.dns1}, 1.0.0.1"
    lines = ["[Interface]", f"Address = {ip}/32", f"DNS = {dns}", f"PrivateKey = {priv}"]
    lines += [f"{k} = {v}" for k, v in srv.client_params.items()]
    lines += [f"{k} = {srv.special[k]}" for k in SPECIAL if k in srv.special]
    lines += ["", "[Peer]", f"PublicKey = {srv.server_pub}"]
    if srv.psk:
        lines.append(f"PresharedKey = {srv.psk}")
    lines += ["AllowedIPs = 0.0.0.0/0, ::/0", f"Endpoint = {endpoint_host}:{srv.listen_port}",
              f"PersistentKeepalive = {srv.keepalive}"]
    return "\n".join(lines) + "\n"


def _client_key(srv: AwgServer, ip: str, priv: str, pub: str, host: str, description: str) -> str:
    """Обычный ключ vpn:// в формате приложения Amnezia (как «Поделиться» → «Ключ Amnezia»)."""
    last = dict(srv.client_params)
    last.update({k: srv.special[k] for k in SPECIAL if k in srv.special})
    last.update({
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "clientId": pub,
        "client_ip": ip,
        "client_priv_key": priv,
        "client_pub_key": pub,
        "config": _client_conf(srv, ip, priv, host, dns_placeholders=True),
        "hostName": host,
        "mtu": CLIENT_MTU,
        "persistent_keep_alive": srv.keepalive,
        "port": srv.listen_port,
        "psk_key": srv.psk,
        "server_pub_key": srv.server_pub,
    })
    awg = srv.awg_block()
    awg["last_config"] = json.dumps(last, ensure_ascii=False, indent=4)
    config = {
        "containers": [{"awg": awg, "container": srv.container}],
        "defaultContainer": srv.container,
        "description": description,
        "dns1": srv.dns1,
        "dns2": "1.0.0.1",
        "format_version": 1,
        "hostName": host,
    }
    return encode_vpn(json.dumps(config, ensure_ascii=False, indent=4))


# --------------------------------------------------------------------------- #
#  Сценарии
# --------------------------------------------------------------------------- #

def create_user_key(p: core.Params, name: str, log: core.Log) -> UserKey:
    name = name.strip() or "Relay Connect"
    ru, de, ru_ip, _ = core.connect_pair(p, log)
    try:
        log("Читаю настройки AmneziaWG на зарубежном сервере…", "step")
        srv = find_awg(de, log)

        if not any(port == srv.listen_port and '"realm"' in line for _, port, line in core.listeners(ru, "udp")):
            log(f"RU-сервер не пересылает порт {srv.listen_port}/udp — ключ не заработает, "
                "пока не нажмёшь «Настроить»", "warn")

        log(f"Создаю пользователя «{name}»…", "step")
        _, keys, _ = de.run(srv.in_container(f"k=$({srv.tool} genkey); echo $k; echo $k | {srv.tool} pubkey"),
                            check=True)
        try:
            priv, pub = keys.split()[:2]
        except ValueError:
            raise core.RelayError(f"Не удалось сгенерировать ключи ({srv.tool} genkey)") from None
        ip = _next_ip(srv)

        peer = "\n[Peer]\nPublicKey = {}\n{}AllowedIPs = {}/32\n".format(
            pub, f"PresharedKey = {srv.psk}\n" if srv.psk else "", ip)
        backup = f"{srv.conf_path}.relay-connect.bak"
        de.run(f"docker exec {srv.container} cp {srv.conf_path} {backup}", check=True)
        de.run(f"{_pipe(peer)} | docker exec -i {srv.container} sh -c 'cat >> {srv.conf_path}'", check=True)
        if not _apply(de, srv):
            de.run(f"docker exec {srv.container} cp {backup} {srv.conf_path}")
            _apply(de, srv)
            raise core.RelayError("AmneziaWG не принял нового пользователя — конфиг сервера возвращён как был")
        log(f"Пользователь «{name}» добавлен, адрес в туннеле {ip}", "ok")

        _add_client_name(de, srv, pub, name, log)
        conf = _client_conf(srv, ip, priv, ru_ip)
        vpn = _client_key(srv, ip, priv, pub, ru_ip, f"{name} (relay {ru_ip})")
        log(f"Ключ готов: подключение через RU-сервер {ru_ip}:{srv.listen_port}", "ok")
        return UserKey(name=name, ip=ip, conf=conf, vpn=vpn)
    finally:
        de.close()
        ru.close()


def build_admin_key(p: core.Params, ssh_forward: int, log: core.Log) -> str:
    ru, de, ru_ip, _ = core.connect_pair(p, log)
    try:
        if not any(port == ssh_forward and '"realm"' in line for _, port, line in core.listeners(ru, "tcp")):
            raise core.RelayError(
                f"На RU-сервере нет SSH-проброса на порт {ssh_forward}. Впиши этот порт в поле «SSH-проброс» "
                "на вкладке «Настройка» и нажми «Настроить».")
        _, banner, _ = ru.run(f"timeout 8 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{ssh_forward}; head -c 4 <&3'",
                              timeout=20)
        if banner.startswith("SSH-"):
            log(f"SSH-проброс {ru_ip}:{ssh_forward} → зарубежный сервер работает", "ok")
        else:
            log(f"SSH-проброс на порт {ssh_forward} не ответил — приложение может не подключиться к серверу", "warn")

        log("Читаю настройки AmneziaWG на зарубежном сервере…", "step")
        srv = find_awg(de, log)
        config = {
            "containers": [{"awg": srv.awg_block(), "container": srv.container}],
            "defaultContainer": srv.container,
            "description": f"Relay {ru_ip}",
            "dns1": srv.dns1,
            "dns2": "1.0.0.1",
            "format_version": 1,
            "hostName": ru_ip,
            "userName": p.foreign.user,
            "password": p.foreign.password,
            "port": ssh_forward,
        }
        if srv.other_containers:
            log("В админский ключ попадает только AmneziaWG; другие протоколы на сервере ("
                + ", ".join(srv.other_containers) + ") приложение не увидит", "warn")
        log("Админский ключ готов. В нём root-пароль зарубежного сервера — никому его не отправляй.", "ok")
        return encode_vpn(json.dumps(config, ensure_ascii=False, indent=4))
    finally:
        de.close()
        ru.close()
