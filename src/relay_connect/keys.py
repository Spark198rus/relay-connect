"""
Выдача ключей через relay. Программа сама определяет, как на зарубежном сервере стоит AmneziaWG:

  amneziawg-installer          → keys_installer: клиентов создаёт manage_amneziawg.sh, адрес RU-сервера
                                 попадает в ключи через AWG_ENDPOINT; есть ключи уже существующих клиентов;
  приложение Amnezia (docker)  → keys_docker: пользователь дописывается в конфиг контейнера,
                                 ключ собирается программой; есть админский ключ для приложения Amnezia.
"""

from __future__ import annotations

from typing import Callable, TypeVar

from . import keys_docker, keys_installer
from . import relay_core as core
from .keys_installer import UserKey, client_name  # noqa: F401  (используются в GUI и тестах)

T = TypeVar("T")


def _with_server(p: core.Params, log: core.Log, fn: Callable[[core.Remote, core.Remote, str, str], T]) -> T:
    """Подключается к серверам, определяет вариант AmneziaWG и вызывает fn(ru, de, ru_ip, kind)."""
    ru, de, ru_ip, _ = core.connect_pair(p, log)
    try:
        kind, step = core.detect_amnezia(de)
        if kind not in ("installer", "docker"):
            raise core.RelayError(f"{core.AwgMissing(step)} Сначала нажми «Настроить» на вкладке «Настройка»: "
                                  "программа предложит поставить AmneziaWG.")
        return fn(ru, de, ru_ip, kind)
    finally:
        de.close()
        ru.close()


def create_user_key(p: core.Params, name: str, log: core.Log) -> UserKey:
    def run(ru, de, ru_ip, kind):
        mod = keys_installer if kind == "installer" else keys_docker
        return mod.create_user_key(ru, de, ru_ip, name, log)
    return _with_server(p, log, run)


def get_user_key(p: core.Params, name: str, log: core.Log) -> UserKey:
    def run(ru, de, ru_ip, kind):
        if kind == "docker":
            raise core.RelayError(
                "Amnezia в docker не хранит на сервере ключи пользователей, поэтому показать ключ существующего "
                "нельзя. Возьми его в приложении Amnezia («Поделиться») и поменяй адрес на вкладке "
                "«Конфиг клиента» — или создай новый.")
        return keys_installer.get_user_key(ru, de, ru_ip, name, log)
    return _with_server(p, log, run)


def build_admin_key(p: core.Params, ssh_forward: int, log: core.Log) -> str:
    def run(ru, de, ru_ip, kind):
        if kind == "installer":
            raise core.RelayError(
                "Админский ключ работает только с Amnezia, поставленной приложением Amnezia (docker): "
                "сервером amneziawg-installer приложение управлять не умеет. Клиентов создавай здесь, на вкладке "
                "«Ключи», или на сервере: bash /root/awg/manage_amneziawg.sh add <имя>.")
        return keys_docker.build_admin_key(ru, de, ru_ip, p, ssh_forward, log)
    return _with_server(p, log, run)
