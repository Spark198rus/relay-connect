"""
Relay Connect — ядро.

Схема:
    Клиент (Россия) --IPv4--> RU-сервер:PORT --(realm)--IPv6--> зарубежный сервер:PORT (Amnezia)

На RU-сервер ставится realm (лёгкий L4-форвардер TCP/UDP) как systemd-сервис.
Зарубежный сервер почти не трогаем: только проверяем, что порты Amnezia
доступны по IPv6, и при необходимости открываем их в фаерволе.
"""

from __future__ import annotations

import ipaddress
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

Log = Callable[[str, str], None]   # (сообщение, уровень: info/ok/warn/err/step)


class RelayError(Exception):
    """Ошибка, понятная пользователю."""


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
    ssh_forward: int | None = None  # порт на RU для SSH к зарубежному серверу (админский ключ); None = не нужен


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
            "AllowTcpForwarding."
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


def detect_amnezia_ports(de: Remote, log: Log) -> list[PortSpec]:
    if not de.has("docker"):
        raise RelayError("На зарубежном сервере нет docker — не могу сам найти порты Amnezia. "
                         "Впиши порты вручную (например 51820/udp).")
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
        r.run(f"ufw allow {p}/{proto}", check=True)
        log(f"[{r.name}] ufw: открыт {spec}", "info")
        return
    if r.ok("firewall-cmd --state >/dev/null 2>&1"):
        # Без --reload: reload у firewalld может снести iptables-правила Docker
        # и уронить сеть контейнеров Amnezia. Добавляем правило в runtime и в permanent отдельно.
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
    в файл и динамические правила Docker, которые после перезагрузки задвоятся.
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
    """Порт SSH-проброса на RU-сервере (для админского ключа) или None."""
    if not p.ssh_forward:
        return None
    spec = PortSpec(p.ssh_forward, "tcp")
    if spec in ports:
        raise RelayError(f"Порт SSH-проброса {spec} совпадает с портом Amnezia — выбери другой, например 2222")
    return spec


def _prepare(p: Params, log: Log) -> tuple[Remote, Remote, str, str, list[PortSpec]]:
    ru, de, ru_ip, v6 = connect_pair(p, log)
    ports = p.ports
    if not ports:
        log("Ищу порты Amnezia на зарубежном сервере…", "step")
        ports = detect_amnezia_ports(de, log)
    log("Порты для проброса: " + ", ".join(map(str, ports)), "info")
    return ru, de, ru_ip, v6, ports


def run_check(p: Params, log: Log) -> bool:
    ru = de = None
    try:
        ru, de, _, v6, ports = _prepare(p, log)
        log("Проверяю зарубежный сервер…", "step")
        check_foreign(de, v6, ports, log)
        log("Проверяю RU-сервер…", "step")
        fwd = _forward_spec(p, ports)
        check_ru(ru, v6, ports + ([fwd] if fwd else []), log)
        log("Проверка закончена — можно жать «Настроить».", "ok")
        return True
    finally:
        for r in (de, ru):
            if r:
                r.close()


def run_setup(p: Params, log: Log) -> tuple[str, list[PortSpec]]:
    ru = de = None
    try:
        ru, de, ru_ip, v6, ports = _prepare(p, log)

        log("Зарубежный сервер: проверка и подготовка…", "step")
        missing = check_foreign(de, v6, ports, log)
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
            # SSH-проброс: RU:<fwd> → зарубежный сервер [IPv6]:<его SSH-порт>, для админского ключа Amnezia
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

        log("", "info")
        log(f"ГОТОВО. В клиенте Amnezia замени адрес сервера на {ru_ip} (порты те же: "
            + ", ".join(map(str, ports)) + "). Новые ключи можно выдать на вкладке «Ключи».", "ok")
        return ru_ip, ports
    finally:
        for r in (de, ru):
            if r:
                r.close()


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
