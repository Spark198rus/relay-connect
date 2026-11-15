"""
Relay Connect — ядро.

Схема:
    Клиент (Россия) --IPv4--> RU-сервер:PORT --(realm)--IPv6--> зарубежный сервер:PORT (Amnezia)

На RU-сервер ставится realm (лёгкий L4-форвардер TCP/UDP) как systemd-сервис.

На зарубежном сервере программа сама определяет, как стоит AmneziaWG:
  - скриптом amneziawg-installer (https://github.com/bivlked/amneziawg-installer): модуль ядра,
    сервис awg-quick@awg0, конфиг /etc/amnezia/amneziawg/awg0.conf, клиенты и manage_amneziawg.sh
    в /root/awg. Программа прописывает в настройки установщика (AWG_ENDPOINT) IPv4 RU-сервера,
    чтобы ключи клиентов вели на relay;
  - приложением Amnezia (контейнеры amnezia-* в docker). Порты берутся из docker ps;
  - никак. Тогда программа с согласия пользователя ставит AmneziaWG скриптом amneziawg-installer
    (install_awg) и продолжает настройку.
Уже установленный AmneziaWG программа не переустанавливает.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import shlex
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

import paramiko

REALM_VERSION = "v2.9.6"
REALM_URL = (
    "https://github.com/zhboner/realm/releases/download/"
    f"{REALM_VERSION}/realm-{{arch}}-unknown-linux-musl.tar.gz"
)
ARCH_MAP = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}

SERVICE = "relay-connect"          # relay-connect@udp / relay-connect@tcp
CONF_DIR = "/etc/relay-connect"
REALM_BIN = "/usr/local/bin/realm"

UNIT_TEMPLATE = """[Unit]
Description=Relay Connect (%i): IPv4 -> IPv6 forwarder (realm)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/realm -c /etc/relay-connect/%i.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
"""

SYSCTL_CONF = """# relay-connect: буферы побольше для UDP (WireGuard/AmneziaWG)
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
"""

# amneziawg-installer: пути одинаковые у русской и английской версии
AWG_DIR = "/root/awg"
AWG_MANAGE = f"{AWG_DIR}/manage_amneziawg.sh"
AWG_INIT = f"{AWG_DIR}/awgsetup_cfg.init"      # настройки установщика, строки вида export KEY='value'
AWG_SERVER_CONF = "/etc/amnezia/amneziawg/awg0.conf"
AWG_UNIT = "awg-quick@awg0"
AWG_STATE = f"{AWG_DIR}/setup_state"           # есть, пока установка не закончена: номер следующего шага
AWG_LOG = f"{AWG_DIR}/install_amneziawg.log"
INSTALLER_URL = "https://github.com/bivlked/amneziawg-installer"
INSTALLER_SCRIPT_URL = f"{INSTALLER_URL}/releases/latest/download/install_amneziawg.sh"
INSTALLER_PATH = "/root/install_amneziawg.sh"
INSTALLER_OUT = "/root/relay-connect-awg-install.out"   # вывод установщика, который программа читает
# --allow-ipv6: иначе установщик выключит IPv6, а relay ходит на сервер именно по нему;
# --keep-packages: не удалять snapd/cloud-init и прочее, что уже стоит на сервере
INSTALLER_FLAGS = "--yes --no-color --allow-ipv6 --keep-packages"
INSTALLER_OS = {("ubuntu", "24.04"), ("ubuntu", "26.04"), ("debian", "12"), ("debian", "13")}
INSTALL_TIMEOUT = 90 * 60
# строка sysctl, которой установщик (по умолчанию, без --allow-ipv6) выключает IPv6 на сервере
IPV6_OFF_RE = r"^[[:space:]]*net\.ipv6\.conf\.(all|default|lo)\.disable_ipv6[[:space:]]*=[[:space:]]*1[[:space:]]*$"

Log = Callable[[str, str], None]   # (сообщение, уровень: info/ok/warn/err/step)


class RelayError(Exception):
    """Ошибка, понятная пользователю."""


class AwgMissing(RelayError):
    """На зарубежном сервере нет AmneziaWG (или установка не закончена): можно поставить install_awg."""

    def __init__(self, step: str = ""):
        self.step = step   # "" = ничего не стоит; иначе шаг, на котором остановился amneziawg-installer
        if step:
            msg = (f"На зарубежном сервере не закончена установка amneziawg-installer (остановилась перед шагом "
                   f"{step}, лог: {AWG_LOG}).")
        else:
            msg = ("На зарубежном сервере не найден AmneziaWG: нет ни amneziawg-installer "
                   f"({AWG_SERVER_CONF}), ни контейнеров Amnezia в docker.")
        super().__init__(msg)


def install_question(e: AwgMissing) -> str:
    """Текст вопроса перед установкой — одинаковый в настольной и мобильной версии."""
    head = (f"Установка amneziawg-installer на зарубежном сервере не закончена (следующий шаг {e.step}). "
            "Продолжить её?" if e.step else
            "На зарубежном сервере не найден AmneziaWG. Поставить его скриптом amneziawg-installer?")
    return (head + "\n\n"
            "Что произойдёт на зарубежном сервере:\n"
            "• обновятся пакеты системы, сервер два раза перезагрузится; всё займёт 10–30 минут;\n"
            "• включится фаервол UFW: входящие подключения закрыты, кроме SSH и порта AmneziaWG; "
            "поставится Fail2Ban;\n"
            "• IPv6 останется включённым, ключи клиентов сразу будут вести на RU-сервер.\n\n"
            "Подходят Ubuntu 24.04/26.04 и Debian 12/13. Если на сервере работает что-то ещё, "
            "UFW может закрыть к нему доступ. После установки программа сама продолжит настройку relay.")


# --------------------------------------------------------------------------- #
#  Параметры
# --------------------------------------------------------------------------- #

@dataclass
class ServerCreds:
    host: str
    port: int = 22
    user: str = "root"
    password: str = ""


@dataclass
class PortSpec:
    port: int
    proto: str  # "udp" | "tcp"

    def __str__(self) -> str:
        return f"{self.port}/{self.proto}"

    def __hash__(self):
        return hash((self.port, self.proto))


@dataclass
class Params:
    ru: ServerCreds
    foreign: ServerCreds          # host = IPv6
    ports: list[PortSpec] = field(default_factory=list)  # пусто = автоопределение
    ssh_forward: int | None = None  # порт на RU для SSH к зарубежному серверу (и админского ключа Amnezia
                                    # в docker); None = не нужен


def parse_ports(text: str) -> list[PortSpec]:
    """'51820/udp, 443/tcp, 8443' -> [...]. Без протокола = udp."""
    res: list[PortSpec] = []
    for chunk in re.split(r"[,\s;]+", text.strip()):
        if not chunk:
            continue
        m = re.fullmatch(r"(\d{1,5})(?:/(udp|tcp))?", chunk.lower())
        if not m:
            raise RelayError(f"Не понял порт «{chunk}». Формат: 51820/udp, 443/tcp")
        p = int(m.group(1))
        if not 1 <= p <= 65535:
            raise RelayError(f"Порт вне диапазона: {p}")
        spec = PortSpec(p, m.group(2) or "udp")
        if spec not in res:
            res.append(spec)
    return res


def norm_v4(s: str) -> str:
    try:
        return str(ipaddress.IPv4Address(s.strip()))
    except ValueError:
        raise RelayError(f"«{s}» — это не IPv4-адрес") from None


def norm_v6(s: str) -> str:
    s = s.strip().strip("[]")
    try:
        a = ipaddress.IPv6Address(s)
    except ValueError:
        raise RelayError(f"«{s}» — это не IPv6-адрес") from None
    if not a.is_global:
        raise RelayError(f"{a} — не публичный (global) IPv6-адрес")
    if int(a) & ((1 << 64) - 1) == 0:
        # Младшие 64 бита нулевые = адрес подсети (Subnet-Router anycast):
        # на него отвечает маршрутизатор хостера, поэтому ping идёт, а TCP/UDP до сервера — нет.
        raise RelayError(
            f"{a} — это адрес подсети, а не сервера (после последнего «::» нет цифр). "
            "На такой адрес отвечает маршрутизатор хостера, поэтому ping проходит, а подключения — нет. "
            "Возьми точный адрес из `ip -6 addr show scope global` на зарубежном сервере: "
            "обычно он заканчивается на ::1 или ::2.")
    return str(a)


# --------------------------------------------------------------------------- #
#  SSH
# --------------------------------------------------------------------------- #

class Remote:
    def __init__(self, name: str, client: paramiko.SSHClient, log: Log):
        self.name = name
        self.client = client
        self.log = log

    def run(self, cmd: str, timeout: int = 180, check: bool = False) -> tuple[int, str, str]:
        full = "export LC_ALL=C DEBIAN_FRONTEND=noninteractive " \
               "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; " + cmd
        _, so, se = self.client.exec_command("bash -c " + shlex.quote(full), timeout=timeout)
        out = so.read().decode("utf-8", "replace")
        err = se.read().decode("utf-8", "replace")
        code = so.channel.recv_exit_status()
        if check and code != 0:
            raise RelayError(f"[{self.name}] команда упала (код {code}): {cmd}\n{err.strip() or out.strip()}")
        return code, out, err

    def ok(self, cmd: str, timeout: int = 60) -> bool:
        return self.run(cmd, timeout=timeout)[0] == 0

    def has(self, binary: str) -> bool:
        return self.ok(f"command -v {shlex.quote(binary)} >/dev/null 2>&1")

    def write(self, path: str, content: str | bytes, mode: int = 0o644):
        data = content.encode() if isinstance(content, str) else content
        sftp = self.client.open_sftp()
        try:
            with sftp.open(path, "wb") as f:
                f.write(data)
            sftp.chmod(path, mode)
        finally:
            sftp.close()

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass


def _ssh(creds: ServerCreds, sock=None) -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        creds.host, port=creds.port, username=creds.user, password=creds.password,
        sock=sock, timeout=15, banner_timeout=30, auth_timeout=30,
        look_for_keys=False, allow_agent=False,
    )
    return c


def connect_ru(creds: ServerCreds, log: Log) -> Remote:
    log(f"Подключаюсь к RU-серверу {creds.host}:{creds.port}…", "info")
    try:
        c = _ssh(creds)
    except paramiko.AuthenticationException:
        raise RelayError("RU-сервер: неверный логин или пароль") from None
    except (OSError, paramiko.SSHException) as e:
        raise RelayError(f"RU-сервер: не удалось подключиться по SSH: {e}") from None
    r = Remote("RU", c, log)
    _require_root(r)
    log("RU-сервер: подключено", "ok")
    return r


def connect_foreign(creds: ServerCreds, ru: Remote, log: Log) -> Remote:
    """Сначала через RU-сервер (IPv6 jump), иначе напрямую (если у ПК есть IPv6)."""
    log(f"Подключаюсь к зарубежному серверу [{creds.host}]:{creds.port} через RU-сервер (по IPv6)…", "info")
    jump_err = None
    try:
        chan = ru.client.get_transport().open_channel(
            "direct-tcpip", (creds.host, creds.port), ("127.0.0.1", 0), timeout=20)
        c = _ssh(creds, sock=chan)
        r = Remote("DE", c, log)
        _require_root(r)
        log("Зарубежный сервер: подключено через RU-сервер — IPv6-связность RU→DE есть", "ok")
        return r
    except paramiko.AuthenticationException:
        raise RelayError("Зарубежный сервер: неверный логин или пароль") from None
    except RelayError:
        raise
    except Exception as e:
        jump_err = e
    log(f"Через RU-сервер не вышло ({jump_err}). Пробую напрямую с этого ПК…", "warn")
    try:
        c = _ssh(creds)
    except paramiko.AuthenticationException:
        raise RelayError("Зарубежный сервер: неверный логин или пароль") from None
    except Exception as e:
        raise RelayError(
            "Не удалось достучаться до зарубежного сервера по IPv6 ни через RU-сервер, ни напрямую.\n"
            f"  через RU: {jump_err}\n  напрямую: {e}\n"
            "Проверь: у зарубежного VPS реально есть IPv6 (в панели хостера), sshd слушает IPv6, "
            "у RU-сервера есть рабочий IPv6 (`ping -6 google.com`), на RU-сервере в sshd не выключен "
            "AllowTcpForwarding.\n"
            "Если AmneziaWG ставился через amneziawg-installer без флага --allow-ipv6, установщик выключил "
            "IPv6 на зарубежном сервере. Как включить обратно: docs/DOCUMENTATION.md, раздел «Подготовка "
            "зарубежного сервера»."
        ) from None
    r = Remote("DE", c, log)
    _require_root(r)
    log("Зарубежный сервер: подключено напрямую. ВНИМАНИЕ: RU→DE по IPv6 ещё проверю отдельно.", "warn")
    return r


def _require_root(r: Remote):
    _, out, _ = r.run("id -u")
    if out.strip() != "0":
        raise RelayError(f"[{r.name}] нужен пользователь root (сейчас uid={out.strip()})")
    if not r.has("systemctl"):
        raise RelayError(f"[{r.name}] нет systemd — поддерживаются только обычные Linux (Ubuntu/Debian/…)")


# --------------------------------------------------------------------------- #
#  Сетевые проверки
# --------------------------------------------------------------------------- #

def listeners(r: Remote, proto: str) -> list[tuple[str, int, str]]:
    """[(addr, port, line)] слушающих сокетов."""
    flag = "u" if proto == "udp" else "t"
    _, out, _ = r.run(f"ss -H -lnp{flag}")
    res = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[3]
        if ":" not in local:
            continue
        host, _, port = local.rpartition(":")
        host = host.strip("[]").split("%")[0]
        try:
            res.append((host, int(port), line))
        except ValueError:
            pass
    return res


# --------------------------------------------------------------------------- #
#  Как стоит AmneziaWG на зарубежном сервере
# --------------------------------------------------------------------------- #

def docker_amnezia(de: Remote) -> list[str]:
    """Имена запущенных контейнеров Amnezia (приложение Amnezia ставит их как amnezia-*)."""
    if not de.has("docker"):
        return []
    _, out, _ = de.run("docker ps --format '{{.Names}}' 2>/dev/null")
    return [n for n in out.split() if n.startswith("amnezia")]


def install_state(de: Remote) -> str:
    """Состояние amneziawg-installer: "done", "none" или номер шага, перед которым он остановился."""
    _, out, _ = de.run(f"if [ -f {AWG_STATE} ]; then head -c 16 {AWG_STATE}; "
                       f"elif [ -f {AWG_SERVER_CONF} ] && [ -f {AWG_MANAGE} ]; then echo done; "
                       # конфиг есть, а скриптов и состояния нет: установщик начнёт заново с шага 1
                       f"elif [ -f {AWG_SERVER_CONF} ]; then echo 1; else echo none; fi", timeout=30)
    return out.strip() or "none"


def detect_amnezia(de: Remote) -> tuple[str, str]:
    """("installer" | "docker" | "partial" | "none", шаг установщика для "partial").

    Установщик проверяем первым: на сервере могут остаться и старые контейнеры Amnezia.
    """
    state = install_state(de)
    if state == "done":
        return "installer", ""
    if docker_amnezia(de):
        return "docker", ""
    if state != "none":
        return "partial", state
    return "none", ""


def detect_amnezia_ports(de: Remote, log: Log) -> list[PortSpec]:
    """Порты, которые контейнеры Amnezia публикуют наружу (docker ps)."""
    _, out, _ = de.run("docker ps --format '{{.Names}}\t{{.Ports}}'")
    found: list[PortSpec] = []
    for line in out.splitlines():
        name, _, ports = line.partition("\t")
        if not name.startswith("amnezia"):
            continue
        for m in re.finditer(r"(\d+)(?:-\d+)?->\d+(?:-\d+)?/(tcp|udp)", ports):
            spec = PortSpec(int(m.group(1)), m.group(2))
            if spec not in found:
                found.append(spec)
                log(f"  найден {spec} у контейнера {name}", "info")
    if not found:
        raise RelayError("Не нашёл контейнеров Amnezia с опубликованными портами (docker ps). "
                         "Впиши порты вручную.")
    return found


# --------------------------------------------------------------------------- #
#  AmneziaWG от amneziawg-installer
# --------------------------------------------------------------------------- #

@dataclass
class AwgServer:
    port: int                     # UDP-порт AmneziaWG (ListenPort)
    endpoint: str                 # AWG_ENDPOINT из awgsetup_cfg.init; "" = установщик сам берёт внешний IPv4
    clients: list[str]            # имена клиентов (#_Name в awg0.conf)
    protocol: str                 # поколение протокола (AWG_PROTOCOL), "" если не записано
    active: bool                  # запущен ли awg-quick@awg0
    ipv6_off_files: list[str]     # sysctl-файлы, которые выключат IPv6 после перезагрузки


def parse_init(text: str) -> dict[str, str]:
    """awgsetup_cfg.init -> {KEY: value}. Формат как у safe_load_config установщика."""
    res: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip().lstrip("﻿")
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
        if not m:
            continue
        value = m.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        res[m.group(1)] = value
    return res


def find_awg(de: Remote, log: Log) -> AwgServer:
    """Находит AmneziaWG, поставленный amneziawg-installer. Ничего не меняет."""
    if not de.ok(f"test -f {AWG_SERVER_CONF}"):
        raise RelayError(f"На зарубежном сервере нет {AWG_SERVER_CONF}: AmneziaWG не установлен через "
                         f"amneziawg-installer ({INSTALLER_URL}).")
    if not de.ok(f"test -f {AWG_MANAGE}"):
        raise RelayError(f"На зарубежном сервере нет {AWG_MANAGE}. Установка amneziawg-installer не "
                         "завершена: запусти установщик ещё раз, он продолжит с того же шага.")

    _, live, _ = de.run("awg show awg0 listen-port 2>/dev/null")
    _, conf_port, _ = de.run(f"sed -n 's/^ListenPort[[:space:]]*=[[:space:]]*//p' {AWG_SERVER_CONF} | head -n 1")
    port_text = (live.strip() or conf_port.strip())
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise RelayError(f"Не нашёл ListenPort в {AWG_SERVER_CONF}. Впиши порт вручную, например 39743/udp.")

    _, init_text, _ = de.run(f"cat {AWG_INIT} 2>/dev/null")
    init = parse_init(init_text)
    _, names, _ = de.run(f"sed -n 's/^#_Name = //p' {AWG_SERVER_CONF}")
    _, off, _ = de.run(f"grep -lE {shlex.quote(IPV6_OFF_RE)} /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null")

    srv = AwgServer(
        port=int(port_text),
        endpoint=init.get("AWG_ENDPOINT", "").strip(),
        clients=[n.strip() for n in names.splitlines() if n.strip()],
        protocol=init.get("AWG_PROTOCOL", ""),
        active=de.ok(f"systemctl is-active --quiet {AWG_UNIT}"),
        ipv6_off_files=off.split(),
    )
    log(f"AmneziaWG{' ' + srv.protocol if srv.protocol else ''} (amneziawg-installer): порт {srv.port}/udp, "
        f"клиентов {len(srv.clients)}, адрес в ключах: {srv.endpoint or 'внешний IPv4 сервера (авто)'}", "ok")
    if not srv.active:
        log(f"Сервис {AWG_UNIT} не запущен — клиенты не подключатся. На зарубежном сервере: "
            f"`bash {AWG_MANAGE} check`, после обновления ядра `bash {AWG_MANAGE} repair-module`", "warn")
    if srv.ipv6_off_files:
        log("На зарубежном сервере IPv6 выключится после перезагрузки (" + ", ".join(srv.ipv6_off_files) +
            ": disable_ipv6 = 1, так делает установщик без --allow-ipv6). «Настроить» это исправит.", "warn")
    return srv


def keep_ipv6(de: Remote, srv: AwgServer, log: Log):
    """Убирает выключение IPv6 из sysctl, иначе relay умрёт при первой перезагрузке зарубежного сервера.

    Правим только строки disable_ipv6 = 1 (меняем на 0) и DISABLE_IPV6 в awgsetup_cfg.init,
    чтобы повторный запуск установщика не выключил IPv6 снова.
    """
    if not srv.ipv6_off_files:
        return
    files = " ".join(shlex.quote(f) for f in srv.ipv6_off_files)
    de.run("sed -i -E 's/^([[:space:]]*net\\.ipv6\\.conf\\.(all|default|lo)\\.disable_ipv6[[:space:]]*="
           f"[[:space:]]*)1[[:space:]]*$/\\10/' {files}", check=True)
    de.run(f"test -f {AWG_INIT} && sed -i -E 's/^(export )?DISABLE_IPV6=.*/export DISABLE_IPV6=0/' {AWG_INIT}")
    srv.ipv6_off_files = []
    log("Зарубежный сервер: IPv6 больше не выключается при загрузке (disable_ipv6 = 0, DISABLE_IPV6=0)", "ok")


def awg_manage(de: Remote, args: str, timeout: int = 600) -> dict:
    """Запускает manage_amneziawg.sh с --json и возвращает его ответ."""
    code, out, err = de.run(f"bash {AWG_MANAGE} --json --no-color --yes {args}", timeout=timeout)
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                res = json.loads(line)
            except json.JSONDecodeError:
                break
            if isinstance(res, dict):
                res.setdefault("rc", code)
                return res
            break
    tail = "\n".join((err.strip() or out.strip()).splitlines()[-15:])
    raise RelayError(f"manage_amneziawg.sh {args}: не понял ответ (код {code}).\n{tail}")


def point_clients_to_relay(de: Remote, srv: AwgServer, ru_ip: str, log: Log):
    """Прописывает IPv4 RU-сервера в AWG_ENDPOINT и перевыпускает файлы клиентов.

    После этого `manage add`/`regen` сами пишут в ключи Endpoint = RU-сервер, а AllowedIPs
    исключают именно адрес RU-сервера (иначе awg-quick на Linux завернёт в туннель пакеты к relay).
    """
    if srv.endpoint == ru_ip:
        log(f"Ключи клиентов уже ведут на RU-сервер {ru_ip}", "ok")
        return
    if not de.ok(f"test -f {AWG_INIT}"):
        raise RelayError(f"На зарубежном сервере нет {AWG_INIT}: установка amneziawg-installer не завершена")
    # копия настроек до первого изменения (cp -n не перезапишет её при повторной настройке)
    de.run(f"cp -n {AWG_INIT} {AWG_INIT}.relay-connect.bak")
    line = f"export AWG_ENDPOINT='{ru_ip}'"
    de.run(f"if grep -qE '^(export )?AWG_ENDPOINT=' {AWG_INIT}; then "
           f"sed -i -E \"s/^(export )?AWG_ENDPOINT=.*/{line}/\" {AWG_INIT}; "
           f"else echo \"{line}\" >> {AWG_INIT}; fi", check=True)
    log(f"Адрес в ключах клиентов: {srv.endpoint or 'авто'} → {ru_ip} (AWG_ENDPOINT в {AWG_INIT}, "
        f"прежние настройки сохранены в {AWG_INIT}.relay-connect.bak)", "ok")
    srv.endpoint = ru_ip
    if not srv.clients:
        return
    log(f"Перевыпускаю файлы {len(srv.clients)} клиентов с адресом RU-сервера (manage regen)…", "info")
    res = awg_manage(de, "regen")
    failed = [r.get("name", "?") for r in res.get("results", []) if r.get("status") != "regenerated"]
    log(f"Перевыпущено клиентов: {res.get('regenerated', 0)}. Ключи клиентов: "
        + ", ".join(srv.clients) + ". Их можно получить на вкладке «Ключи» кнопкой «Показать ключ существующего» "
        "и заново импортировать на устройствах.", "ok" if res.get("ok") else "warn")
    if not res.get("ok"):
        log("manage regen завершился с ошибкой" + (f" для: {', '.join(failed)}" if failed else "") +
            f". Подробности на зарубежном сервере: `bash {AWG_MANAGE} regen`", "warn")


def check_foreign(de: Remote, v6: str, ports: list[PortSpec], log: Log) -> list[PortSpec]:
    """Возвращает порты, которые НЕ слушаются по IPv6 (нужно чинить)."""
    _, out, _ = de.run("ip -6 addr show scope global")
    addrs = set()
    for m in re.finditer(r"inet6\s+([0-9a-f:]+)/\d+", out):
        try:
            addrs.add(str(ipaddress.IPv6Address(m.group(1))))
        except ValueError:
            pass
    if v6 in addrs:
        log(f"Зарубежный сервер: адрес {v6} настроен на интерфейсе", "ok")
    elif addrs:
        log(f"Зарубежный сервер: {v6} нет среди адресов интерфейса ({', '.join(sorted(addrs))}). "
            "Проверь, что указал правильный IPv6.", "warn")
    else:
        raise RelayError("На зарубежном сервере нет ни одного глобального IPv6-адреса. "
                         "Включи IPv6 в панели хостера и на сервере.")

    missing = []
    for spec in ports:
        ok = False
        for host, port, _ in listeners(de, spec.proto):
            if port != spec.port:
                continue
            if host in ("::", "*"):
                ok = True
            else:
                try:
                    ok = ok or str(ipaddress.ip_address(host)) == v6
                except ValueError:
                    pass
        if ok:
            log(f"Зарубежный сервер: {spec} слушается по IPv6", "ok")
        else:
            log(f"Зарубежный сервер: {spec} НЕ слушается по IPv6 — поставлю мост [{v6}]→127.0.0.1", "warn")
            missing.append(spec)
    return missing


def check_ru(ru: Remote, v6: str, ports: list[PortSpec], log: Log):
    code, out, _ = ru.run(f"ip -6 route get {v6}")
    if code != 0:
        raise RelayError("У RU-сервера нет IPv6-маршрута до зарубежного сервера. "
                         "Нужен российский VPS с IPv6 (включи его в панели хостера).")
    log("RU-сервер: IPv6-маршрут до зарубежного сервера есть", "ok")
    if ru.has("ping"):
        if ru.ok(f"ping -6 -c 3 -W 2 {v6} >/dev/null 2>&1", timeout=30):
            log("RU-сервер: ping по IPv6 до зарубежного сервера проходит", "ok")
        else:
            log("RU-сервер: ping по IPv6 не проходит (может быть просто запрещён ICMP)", "warn")

    busy = []
    for spec in ports:
        for host, port, line in listeners(ru, spec.proto):
            if port == spec.port and '"realm"' not in line:
                busy.append(f"{spec} (занят: {line.split()[-1] if 'users:' in line else host})")
                break
    if busy:
        raise RelayError("На RU-сервере уже заняты порты: " + "; ".join(busy) +
                         ". Освободи их или поменяй порт в Amnezia.")
    log("RU-сервер: нужные порты свободны", "ok")


# --------------------------------------------------------------------------- #
#  Фаервол
# --------------------------------------------------------------------------- #

def open_port(r: Remote, spec: PortSpec, family: int, log: Log):
    p, proto = spec.port, spec.proto
    _, out, _ = r.run("ufw status 2>/dev/null | head -1")
    if "Status: active" in out:
        # правило установщика (с комментарием «AmneziaWG VPN») не трогаем, если оно уже есть
        if r.ok(f"ufw show added 2>/dev/null | grep -qE '^ufw allow {p}/{proto}( |$)'"):
            return
        r.run(f"ufw allow {p}/{proto}", check=True)
        log(f"[{r.name}] ufw: открыт {spec}", "info")
        return
    if r.ok("firewall-cmd --state >/dev/null 2>&1"):
        # Без --reload: reload у firewalld сбрасывает правила, добавленные в обход него
        # (NAT AmneziaWG из PostUp, Docker). Добавляем правило в runtime и в permanent отдельно.
        if not r.ok(f"firewall-cmd --query-port={p}/{proto}"):
            r.run(f"firewall-cmd --add-port={p}/{proto}", check=True)
        r.run(f"firewall-cmd --permanent --add-port={p}/{proto}")
        log(f"[{r.name}] firewalld: открыт {spec}", "info")
        return
    ipt = "iptables" if family == 4 else "ip6tables"
    if not r.has(ipt):
        return
    _, rules, _ = r.run(f"{ipt} -S INPUT")
    restrictive = "-P INPUT DROP" in rules or re.search(r"^-A INPUT -j (DROP|REJECT)", rules, re.M)
    if not restrictive:
        return
    rule = f"INPUT -p {proto} --dport {p} -j ACCEPT"
    if not r.ok(f"{ipt} -C {rule}"):
        r.run(f"{ipt} -I {rule}", check=True)
        log(f"[{r.name}] {ipt}: открыт {spec}", "info")
        _persist_rule(r, ipt, rule, log)


def _persist_rule(r: Remote, ipt: str, rule: str, log: Log):
    """Сохраняет ОДНО правило, не трогая остальное.

    Никаких `netfilter-persistent save` / `iptables-save > rules`: они записали бы
    в файл и динамические правила (PostUp AmneziaWG, Docker), которые после перезагрузки задвоятся.
    Вместо этого — отдельный oneshot-сервис, который при загрузке добавляет только наше правило.
    """
    unit = f"relay-connect-fw-{'v6' if ipt == 'ip6tables' else 'v4'}"
    path = f"/etc/relay-connect/{unit}.rules"
    r.run("mkdir -p /etc/relay-connect")
    # файл со списком правил (по одному на строку), без дублей
    r.run(f"touch {path}; grep -qxF {shlex.quote(rule)} {path} || echo {shlex.quote(rule)} >> {path}")
    r.write(f"/etc/systemd/system/{unit}.service", f"""[Unit]
Description=Relay Connect: firewall rules ({ipt})
After=network-pre.target
Before=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'while read -r rule; do [ -n "$$rule" ] && ({ipt} -C $$rule 2>/dev/null || {ipt} -I $$rule); done < {path}'

[Install]
WantedBy=multi-user.target
""")
    r.run(f"systemctl daemon-reload && systemctl enable {unit} >/dev/null 2>&1")
    log(f"[{r.name}] правило {ipt} сохранено на перезагрузку (сервис {unit})", "info")


# --------------------------------------------------------------------------- #
#  realm
# --------------------------------------------------------------------------- #

def _ssl_context():
    """CA-сертификаты из certifi: у Python на macOS (python.org) и Android своих может не быть."""
    import ssl
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def install_realm(r: Remote, log: Log):
    _, ver, _ = r.run(f"{REALM_BIN} --version 2>/dev/null")
    if REALM_VERSION.lstrip("v") in ver:
        log(f"[{r.name}] realm {REALM_VERSION} уже установлен", "info")
        return
    _, arch, _ = r.run("uname -m")
    arch = ARCH_MAP.get(arch.strip())
    if not arch:
        raise RelayError(f"[{r.name}] неподдерживаемая архитектура процессора: {arch}")
    url = REALM_URL.format(arch=arch)
    tgz = "/tmp/relay-connect-realm.tgz"
    log(f"[{r.name}] скачиваю realm {REALM_VERSION}…", "info")
    got = r.ok(f"curl -fsSL --connect-timeout 15 --max-time 180 -o {tgz} {url}", timeout=200) or \
        r.ok(f"wget -q -T 60 -O {tgz} {url}", timeout=200)
    if not got:
        log(f"[{r.name}] сервер не смог скачать с GitHub — качаю на этом ПК и загружаю по SFTP…", "warn")
        try:
            with urllib.request.urlopen(url, timeout=120, context=_ssl_context()) as resp:
                data = resp.read()
        except Exception as e:
            raise RelayError(f"Не удалось скачать realm ни на сервере, ни на ПК: {e}") from None
        r.write(tgz, data, 0o600)
    r.run(f"tar -xzf {tgz} -C /tmp realm && install -m 755 /tmp/realm {REALM_BIN} && rm -f /tmp/realm {tgz}",
          check=True)
    _, ver, _ = r.run(f"{REALM_BIN} --version")
    log(f"[{r.name}] установлен: {ver.strip() or 'realm'}", "ok")


def realm_toml(pairs: list[tuple[str, str]], proto: str) -> str:
    lines = ['[log]', 'level = "warn"', 'output = "stdout"', '', '[network]']
    if proto == "udp":
        lines += ["no_tcp = true", "use_udp = true", "udp_timeout = 180"]
    else:
        lines += ["no_tcp = false", "use_udp = false", "tcp_timeout = 10"]
    for listen, remote in pairs:
        lines += ["", "[[endpoints]]", f'listen = "{listen}"', f'remote = "{remote}"']
    return "\n".join(lines) + "\n"


def deploy_realm(r: Remote, by_proto: dict[str, list[tuple[str, str]]], log: Log, tag: str = ""):
    """by_proto = {'udp': [(listen, remote)], 'tcp': [...]}. tag — префикс имени инстанса."""
    r.run(f"mkdir -p {CONF_DIR}", check=True)
    r.write(f"/etc/systemd/system/{SERVICE}@.service", UNIT_TEMPLATE)
    r.write("/etc/sysctl.d/99-relay-connect.conf", SYSCTL_CONF)
    r.run("sysctl -q -p /etc/sysctl.d/99-relay-connect.conf")
    r.run("systemctl daemon-reload", check=True)
    for proto in ("udp", "tcp"):
        inst = f"{tag}{proto}"
        unit = f"{SERVICE}@{inst}"
        pairs = by_proto.get(proto) or []
        if not pairs:
            r.run(f"systemctl disable --now {unit} 2>/dev/null; rm -f {CONF_DIR}/{inst}.toml")
            continue
        r.write(f"{CONF_DIR}/{inst}.toml", realm_toml(pairs, proto))
        r.run(f"systemctl enable {unit} && systemctl restart {unit}", check=True)
        time.sleep(2)
        if not r.ok(f"systemctl is-active --quiet {unit}"):
            _, j, _ = r.run(f"journalctl -u {unit} -n 20 --no-pager")
            raise RelayError(f"[{r.name}] сервис {unit} не запустился:\n{j}")
        log(f"[{r.name}] сервис {unit} запущен: " + ", ".join(f"{a} → {b}" for a, b in pairs), "ok")


# --------------------------------------------------------------------------- #
#  Сквозная проверка
# --------------------------------------------------------------------------- #

def e2e_test(ru: Remote, de: Remote, v6: str, ports: list[PortSpec], log: Log):
    for spec in ports:
        if spec.proto == "tcp":
            if ru.ok(f"timeout 8 bash -c '</dev/tcp/127.0.0.1/{spec.port}' && "
                     f"timeout 8 bash -c '</dev/tcp/{v6}/{spec.port}'", timeout=20):
                log(f"Проверка {spec}: RU-сервер → зарубежный сервер — соединение есть", "ok")
            else:
                log(f"Проверка {spec}: TCP-соединение до [{v6}]:{spec.port} не установилось", "warn")
            continue
        if not de.has("tcpdump"):
            if de.has("apt-get"):
                de.run("apt-get install -y -qq tcpdump >/dev/null 2>&1", timeout=180)
            if not de.has("tcpdump"):
                log(f"Проверка {spec}: пропущена (нет tcpdump на зарубежном сервере)", "warn")
                continue
        # ловим на DE один пакет, приходящий по IPv6, и шлём мусорный UDP через relay на RU
        _, so, _ = de.client.exec_command(
            f"timeout 12 tcpdump -ni any -c 1 'ip6 and udp dst port {spec.port}' 2>/dev/null")
        time.sleep(2.5)
        for _ in range(5):
            ru.run(f"echo relay-connect-test > /dev/udp/127.0.0.1/{spec.port}")
            time.sleep(0.4)
        out = so.read().decode("utf-8", "replace")
        if out.strip():  # tcpdump печатает строку только если пакет пойман
            log(f"Проверка {spec}: UDP-пакет прошёл RU → (IPv6) → зарубежный сервер", "ok")
        else:
            log(f"Проверка {spec}: тестовый UDP-пакет не дошёл до зарубежного сервера. "
                "Возможно, IPv6 фильтруется у хостера (внешний фаервол в панели).", "warn")


# --------------------------------------------------------------------------- #
#  Сценарии
# --------------------------------------------------------------------------- #

def connect_pair(p: Params, log: Log) -> tuple[Remote, Remote, str, str]:
    """Проверяет адреса и подключается к обоим серверам (к зарубежному — через RU по IPv6)."""
    ru_ip = norm_v4(p.ru.host)
    v6 = norm_v6(p.foreign.host)
    p.ru.host, p.foreign.host = ru_ip, v6
    for c, n in ((p.ru, "RU"), (p.foreign, "зарубежного")):
        if not c.password:
            raise RelayError(f"Не указан пароль {n} сервера")
    ru = connect_ru(p.ru, log)
    try:
        de = connect_foreign(p.foreign, ru, log)
    except Exception:
        ru.close()
        raise
    return ru, de, ru_ip, v6


def _forward_spec(p: Params, ports: list[PortSpec]) -> PortSpec | None:
    """Порт SSH-проброса на RU-сервере (SSH к зарубежному серверу через RU) или None."""
    if not p.ssh_forward:
        return None
    spec = PortSpec(p.ssh_forward, "tcp")
    if spec in ports:
        raise RelayError(f"Порт SSH-проброса {spec} совпадает с портом AmneziaWG — выбери другой, например 2222")
    return spec


@dataclass
class _Ctx:
    ru: Remote
    de: Remote
    ru_ip: str
    v6: str
    ports: list[PortSpec]
    kind: str                     # installer | docker | none (порты вписаны вручную)
    srv: AwgServer | None         # AmneziaWG от установщика, если программа правит адрес в его ключах


def _prepare(p: Params, log: Log) -> _Ctx:
    ru, de, ru_ip, v6 = connect_pair(p, log)
    try:
        log("Ищу AmneziaWG на зарубежном сервере…", "step")
        kind, step = detect_amnezia(de)
        srv: AwgServer | None = None
        if kind == "installer":
            srv = find_awg(de, log)
            others = docker_amnezia(de)
            if others:
                log("На сервере есть и контейнеры Amnezia в docker (" + ", ".join(others) + "). Пробрасываю порт "
                    "amneziawg-installer; порты контейнеров, если нужны, впиши в поле «Порты» вручную.", "info")
            ports = p.ports or [PortSpec(srv.port, "udp")]
            if PortSpec(srv.port, "udp") not in ports:
                log(f"Порт AmneziaWG {srv.port}/udp не входит в список портов — адрес в ключах клиентов не меняю",
                    "warn")
                srv = None
        elif kind == "docker":
            log("AmneziaWG поставлен приложением Amnezia (docker): " + ", ".join(docker_amnezia(de)), "ok")
            ports = p.ports or detect_amnezia_ports(de, log)
        elif p.ports:
            # порты вписаны вручную: настраиваем только пересылку, ничего не ставим
            log(f"{AwgMissing(step)} Порты указаны вручную — настраиваю только пересылку.", "warn")
            kind, ports = "none", p.ports
        else:
            raise AwgMissing(step)
    except Exception:
        de.close()
        ru.close()
        raise
    log("Порты для проброса: " + ", ".join(map(str, ports)), "info")
    return _Ctx(ru, de, ru_ip, v6, ports, kind, srv)


def run_check(p: Params, log: Log) -> bool:
    try:
        c = _prepare(p, log)
    except AwgMissing as e:
        log(f"{e} Нажми «Настроить» — программа предложит поставить его скриптом amneziawg-installer.", "warn")
        return False
    try:
        log("Проверяю зарубежный сервер…", "step")
        check_foreign(c.de, c.v6, c.ports, log)
        if c.srv and c.srv.endpoint != c.ru_ip:
            log(f"Ключи клиентов сейчас ведут на {c.srv.endpoint or 'внешний IPv4 сервера'}. «Настроить» пропишет "
                f"{c.ru_ip} в AWG_ENDPOINT и перевыпустит файлы клиентов.", "info")
        log("Проверяю RU-сервер…", "step")
        fwd = _forward_spec(p, c.ports)
        check_ru(c.ru, c.v6, c.ports + ([fwd] if fwd else []), log)
        log("Проверка закончена — можно жать «Настроить».", "ok")
        return True
    finally:
        c.de.close()
        c.ru.close()


def run_setup(p: Params, log: Log) -> tuple[str, list[PortSpec]]:
    """Настраивает relay. Если AmneziaWG на зарубежном сервере нет, бросает AwgMissing до любых изменений."""
    c = _prepare(p, log)
    ru, de, ru_ip, v6, ports, srv = c.ru, c.de, c.ru_ip, c.v6, c.ports, c.srv
    try:
        log("Зарубежный сервер: проверка и подготовка…", "step")
        missing = check_foreign(de, v6, ports, log)
        if srv:
            keep_ipv6(de, srv, log)
        if missing:
            install_realm(de, log)
            bridge: dict[str, list[tuple[str, str]]] = {"udp": [], "tcp": []}
            for s in missing:
                bridge[s.proto].append((f"[{v6}]:{s.port}", f"127.0.0.1:{s.port}"))
            deploy_realm(de, bridge, log, tag="bridge-")
        for s in ports:
            open_port(de, s, 6, log)

        log("RU-сервер: проверка…", "step")
        ru.run(f"systemctl stop '{SERVICE}@udp' '{SERVICE}@tcp' 2>/dev/null")
        fwd = _forward_spec(p, ports)
        ru_ports = ports + ([fwd] if fwd else [])
        check_ru(ru, v6, ru_ports, log)

        log("RU-сервер: установка relay…", "step")
        install_realm(ru, log)
        by_proto: dict[str, list[tuple[str, str]]] = {"udp": [], "tcp": []}
        for s in ports:
            by_proto[s.proto].append((f"0.0.0.0:{s.port}", f"[{v6}]:{s.port}"))
        if fwd:
            # SSH-проброс: RU:<fwd> → зарубежный сервер [IPv6]:<его SSH-порт>: управлять им, пока IPv4 заблокирован
            by_proto["tcp"].append((f"0.0.0.0:{fwd.port}", f"[{v6}]:{p.foreign.port}"))
        deploy_realm(ru, by_proto, log)
        for s in ru_ports:
            open_port(ru, s, 4, log)

        log("Сквозная проверка…", "step")
        e2e_test(ru, de, v6, ports, log)
        if fwd:
            _, banner, _ = ru.run(f"timeout 8 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{fwd.port}; head -c 4 <&3'",
                                  timeout=20)
            if banner.startswith("SSH-"):
                log(f"Проверка SSH-проброса {ru_ip}:{fwd.port}: зарубежный сервер отвечает", "ok")
            else:
                log(f"Проверка SSH-проброса: на порт {fwd.port} не пришёл ответ SSH от зарубежного сервера", "warn")

        if srv:
            log("Ключи клиентов: адрес RU-сервера…", "step")
            point_clients_to_relay(de, srv, ru_ip, log)

        log("", "info")
        port_list = ", ".join(map(str, ports))
        if c.kind == "installer":
            log(f"ГОТОВО. Клиенты подключаются к {ru_ip} (порты те же: {port_list}). "
                "Ключи для устройств — на вкладке «Ключи».", "ok")
        elif c.kind == "none":
            log(f"ГОТОВО. RU-сервер {ru_ip} пересылает {port_list} на зарубежный сервер: в клиентах укажи адрес "
                f"{ru_ip} (вкладка «Конфиг клиента»).", "ok")
        else:
            log(f"ГОТОВО. В клиенте Amnezia замени адрес сервера на {ru_ip} (порты те же: {port_list}): "
                "вкладка «Конфиг клиента». Новые ключи можно выдать на вкладке «Ключи».", "ok")
        return ru_ip, ports
    finally:
        de.close()
        ru.close()


def run_remove(p: Params, log: Log):
    ru_ip = norm_v4(p.ru.host)
    p.ru.host = ru_ip
    if not p.ru.password:
        raise RelayError("Не указан пароль RU-сервера")
    ru = connect_ru(p.ru, log)
    try:
        ru.run(f"systemctl disable --now '{SERVICE}@udp' '{SERVICE}@tcp' 2>/dev/null")
        # сервисы, которые восстанавливают наши iptables-правила при загрузке (сами правила остаются до ребута)
        ru.run("systemctl disable relay-connect-fw-v4 relay-connect-fw-v6 2>/dev/null; "
               "rm -f /etc/systemd/system/relay-connect-fw-v4.service /etc/systemd/system/relay-connect-fw-v6.service")
        ru.run(f"rm -rf {CONF_DIR} /etc/systemd/system/{SERVICE}@.service "
               f"/etc/sysctl.d/99-relay-connect.conf {REALM_BIN}; systemctl daemon-reload")
        log("RU-сервер: relay удалён (правила фаервола, если добавлялись, оставлены).", "ok")
    finally:
        ru.close()


# --------------------------------------------------------------------------- #
#  Установка AmneziaWG (amneziawg-installer), если на зарубежном сервере его нет
# --------------------------------------------------------------------------- #

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
INSTALLER_LINE_RE = re.compile(r"^\[[^\]]*\]\s+(INFO|WARN|ERROR|DEBUG):\s?(.*)$")


def _installer_line(line: str, log: Log):
    """Строку лога установщика — в журнал программы. Вывод apt и прочих программ не показываем."""
    m = INSTALLER_LINE_RE.match(ANSI_RE.sub("", line).rstrip())
    if not m:
        return
    level, text = m.groups()
    if level == "DEBUG" or not text.strip(" =-!#"):
        return
    if text.startswith("###"):
        log(text.strip(" #"), "info")
    else:
        log("  " + text, {"WARN": "warn", "ERROR": "err"}.get(level, "info"))


def _check_installer_os(de: Remote, log: Log):
    _, out, _ = de.run('. /etc/os-release 2>/dev/null; echo "$ID $VERSION_ID $PRETTY_NAME"')
    os_id, _, rest = out.strip().partition(" ")
    version, _, pretty = rest.partition(" ")
    if (os_id, version) not in INSTALLER_OS:
        raise RelayError(f"На зарубежном сервере {pretty or 'неизвестная ОС'}. amneziawg-installer поддерживает "
                         "Ubuntu 24.04/26.04 и Debian 12/13. Переустанови ОС сервера в панели хостера или поставь "
                         "Amnezia через приложение Amnezia (docker) и нажми «Настроить» снова.")
    log(f"Зарубежный сервер: {pretty} — amneziawg-installer её поддерживает", "ok")


def _fetch_installer(de: Remote, log: Log):
    tmp = f"{INSTALLER_PATH}.download"
    log("Скачиваю amneziawg-installer на зарубежный сервер…", "info")
    got = de.ok(f"curl -fsSL --connect-timeout 15 --max-time 120 -o {tmp} {INSTALLER_SCRIPT_URL}", timeout=150) or \
        de.ok(f"wget -q -T 60 -O {tmp} {INSTALLER_SCRIPT_URL}", timeout=150)
    if not got:
        log("Зарубежный сервер не смог скачать установщик с GitHub — качаю на этом ПК. Учти: по ходу установки "
            "он ещё скачивает свои скрипты с GitHub, без доступа к GitHub установка остановится.", "warn")
        try:
            with urllib.request.urlopen(INSTALLER_SCRIPT_URL, timeout=120, context=_ssl_context()) as resp:
                data = resp.read()
        except Exception as e:
            raise RelayError(f"Не удалось скачать amneziawg-installer ни на сервере, ни на ПК: {e}") from None
        de.write(tmp, data, 0o700)
    if not de.ok(f"head -n 1 {tmp} | grep -q '^#!' && grep -q amneziawg {tmp}"):
        de.run(f"rm -f {tmp}")
        raise RelayError(f"Скачался не установщик, а что-то другое ({INSTALLER_SCRIPT_URL})")
    de.run(f"mv -f {tmp} {INSTALLER_PATH} && chmod 700 {INSTALLER_PATH}", check=True)


def _launch_installer(de: Remote, args: str) -> tuple[int, int]:
    """Запускает установщик в фоне (setsid nohup): он переживёт обрыв SSH и сам перезагрузит сервер.

    Возвращает (pid, сколько байт вывода было до запуска).
    """
    _, out, _ = de.run(f"touch {INSTALLER_OUT}; stat -c %s {INSTALLER_OUT}; cd /root && "
                       f"setsid nohup bash {INSTALLER_PATH} {args} </dev/null >>{INSTALLER_OUT} 2>&1 & echo $!",
                       check=True)
    try:
        offset, pid = (int(x) for x in out.split()[:2])
    except ValueError:
        raise RelayError(f"Не удалось запустить установщик на зарубежном сервере: {out.strip()}") from None
    return pid, offset


def _follow_installer(de: Remote, pid: int, offset: int, deadline: float, log: Log) -> bool:
    """Показывает вывод установщика, пока он работает. True — связь оборвалась (сервер перезагружается)."""
    buf = b""
    while time.time() < deadline:
        time.sleep(5)
        try:
            code, out, _ = de.run(f"tail -c +{offset + 1} {INSTALLER_OUT} 2>/dev/null | head -c 262144 | base64 -w0; "
                                  f"echo; kill -0 {pid} 2>/dev/null && echo RUNNING", timeout=40)
        except Exception:
            return True
        if code < 0:          # канал закрылся без кода выхода: sshd остановлен перезагрузкой
            return True
        lines = out.splitlines()
        try:
            data = base64.b64decode(lines[0]) if lines else b""
        except ValueError:
            data = b""
        offset += len(data)
        *complete, buf = (buf + data).split(b"\n")
        for raw in complete:
            _installer_line(raw.decode("utf-8", "replace"), log)
        if "RUNNING" not in lines[1:]:
            if buf:
                _installer_line(buf.decode("utf-8", "replace"), log)
            return False
    raise RelayError(f"Установка идёт дольше {INSTALL_TIMEOUT // 60} минут. Посмотри лог на зарубежном сервере: "
                     f"{AWG_LOG}")


def _wait_reboot(de: Remote, seconds: int = 180) -> bool:
    """True, когда связь с сервером пропала (началась перезагрузка)."""
    until = time.time() + seconds
    while time.time() < until:
        try:
            if de.run("true", timeout=15)[0] != 0:
                return True
        except Exception:
            return True
        time.sleep(5)
    return False


def _reconnect_foreign(p: Params, ru: Remote, log: Log) -> tuple[Remote, Remote]:
    """Ждёт, пока зарубежный сервер вернётся после перезагрузки, и подключается к нему снова через RU."""
    until = time.time() + 15 * 60
    time.sleep(30)
    while time.time() < until:
        try:
            transport = ru.client.get_transport()
            if not transport or not transport.is_active():
                ru.close()
                ru = connect_ru(p.ru, lambda *_: None)
                ru.client.get_transport().set_keepalive(15)
            try:
                chan = ru.client.get_transport().open_channel(
                    "direct-tcpip", (p.foreign.host, p.foreign.port), ("127.0.0.1", 0), timeout=15)
                de = Remote("DE", _ssh(p.foreign, sock=chan), log)
            except paramiko.AuthenticationException:
                raise
            except Exception:
                # как и connect_foreign: если через RU не выходит, пробуем напрямую с ПК
                de = Remote("DE", _ssh(p.foreign), log)
            de.client.get_transport().set_keepalive(15)
            log("Зарубежный сервер снова на связи", "ok")
            return ru, de
        except paramiko.AuthenticationException:
            raise RelayError("Зарубежный сервер после перезагрузки не принял пароль") from None
        except Exception:
            time.sleep(10)
    raise RelayError("Зарубежный сервер не вернулся после перезагрузки за 15 минут. Проверь его в консоли хостера. "
                     "Когда он загрузится, нажми «Настроить» ещё раз: установка продолжится с того же шага.")


def _installer_tail(de: Remote) -> str:
    _, out, _ = de.run(f"tail -n 15 {AWG_LOG} 2>/dev/null || tail -n 15 {INSTALLER_OUT}")
    return ANSI_RE.sub("", out).strip()


def install_awg(p: Params, log: Log):
    """Ставит AmneziaWG скриптом amneziawg-installer (или продолжает прерванную установку).

    Установщик сам дважды перезагружает сервер, и после каждой перезагрузки его надо запустить снова:
    программа ждёт, переподключается через RU-сервер и запускает его с теми же флагами.
    --endpoint = IPv4 RU-сервера, поэтому ключи клиентов сразу ведут на relay.
    """
    ru, de, ru_ip, _ = connect_pair(p, log)
    try:
        for r in (ru, de):
            r.client.get_transport().set_keepalive(15)
        kind, _ = detect_amnezia(de)
        if kind in ("installer", "docker"):
            log("AmneziaWG на зарубежном сервере уже стоит — ставить не нужно", "ok")
            return
        log("Установка AmneziaWG (amneziawg-installer) на зарубежный сервер…", "step")
        _check_installer_os(de, log)
        _fetch_installer(de, log)
        args = f"{INSTALLER_FLAGS} --endpoint={ru_ip}"
        log(f"Запускаю: bash {INSTALLER_PATH} {args}. Это займёт 10–30 минут, сервер два раза перезагрузится. "
            "Не закрывай программу.", "info")
        deadline = time.time() + INSTALL_TIMEOUT
        for _ in range(6):
            pid, offset = _launch_installer(de, args)
            lost = _follow_installer(de, pid, offset, deadline, log)
            if not lost:
                state = install_state(de)
                if state == "done":
                    log("AmneziaWG установлен", "ok")
                    return
                if state not in ("2", "3"):
                    raise RelayError(f"Установщик остановился с ошибкой (следующий шаг: {state}). Последние строки "
                                     f"лога {AWG_LOG}:\n{_installer_tail(de)}\n\nИсправь причину и нажми «Настроить» "
                                     "ещё раз: установка продолжится с того же шага.")
                if not _wait_reboot(de):
                    raise RelayError("Установщик попросил перезагрузку, но сервер не перезагрузился. Перезагрузи его "
                                     "(reboot) и нажми «Настроить» ещё раз: установка продолжится.")
            log("Зарубежный сервер перезагружается, жду его…", "info")
            de.close()
            ru, de = _reconnect_foreign(p, ru, log)
            state = install_state(de)
            if state == "done":
                log("AmneziaWG установлен", "ok")
                return
            log(f"Продолжаю установку (шаг {state})…", "info")
        raise RelayError(f"Установщик перезапускался слишком много раз. Лог на зарубежном сервере: {AWG_LOG}")
    finally:
        de.close()
        ru.close()
