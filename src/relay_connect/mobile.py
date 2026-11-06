"""
Relay Connect — Android-версия (BeeWare Toga). Собирается Briefcase'ом, см. pyproject.toml.

То же ядро, что и у настольной программы (relay_core, config_patch), другой интерфейс:
одна колонка под экран телефона, два раздела переключаются кнопками сверху
(OptionContainer на Android требует лишнюю зависимость Material — обходимся без него).
"""

from __future__ import annotations

import json
import threading
import traceback

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from . import keys
from . import relay_core as core
from .config_patch import PatchError, patch_any

PREFIX = {"ok": "✔ ", "warn": "⚠ ", "err": "✖ ", "step": "\n▶ "}
SAVED_FIELDS = ("ru_host", "ru_port", "ru_user", "de_host", "de_port", "de_user", "ports", "ssh_fwd")  # без паролей


class RelayConnect(toga.App):
    def startup(self):
        self.busy = False
        self._active = "setup"   # какая операция пишет в журнал: setup/check/remove или userkey/adminkey
        self.inputs: dict[str, toga.Widget] = {}

        self.user_key: keys.UserKey | None = None
        self.views = {
            "setup": self._build_setup(),
            "keys": self._build_keys(),
            "patch": self._build_patch(),
        }
        self.tabs = {
            "setup": toga.Button("Настройка", on_press=lambda w, **k: self._show("setup"), style=Pack(flex=1)),
            "keys": toga.Button("Ключи", on_press=lambda w, **k: self._show("keys"), style=Pack(flex=1)),
            "patch": toga.Button("Переделать", on_press=lambda w, **k: self._show("patch"), style=Pack(flex=1)),
        }
        tabs = toga.Box(children=list(self.tabs.values()), style=Pack(direction=ROW, margin=6, gap=6))

        self.scroll = toga.ScrollContainer(horizontal=False, style=Pack(flex=1))
        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = toga.Box(children=[tabs, self.scroll], style=Pack(direction=COLUMN, flex=1))
        self._show("setup")
        self._load_settings()
        self.main_window.show()

    # ------------------------------------------------------------------ UI --

    @staticmethod
    def _title(text: str) -> toga.Label:
        return toga.Label(text, style=Pack(font_weight="bold", font_size=15, margin=(14, 0, 4, 0)))

    @staticmethod
    def _hint(text: str) -> toga.Label:
        return toga.Label(text, style=Pack(font_size=11, margin=(0, 0, 6, 0)))

    def _field(self, key: str, label: str, placeholder: str = "", value: str = "",
               password: bool = False) -> toga.Box:
        cls = toga.PasswordInput if password else toga.TextInput
        widget = cls(value=value, placeholder=placeholder, style=Pack(flex=1))
        self.inputs[key] = widget
        return toga.Box(children=[toga.Label(label, style=Pack(font_size=12)), widget],
                        style=Pack(direction=COLUMN, margin=(4, 0)))

    def _build_setup(self) -> toga.Box:
        self.btn_check = toga.Button("1. Проверить", on_press=self.on_check, style=Pack(flex=1))
        self.btn_setup = toga.Button("2. Настроить", on_press=self.on_setup, style=Pack(flex=1))
        self.btn_remove = toga.Button("Удалить relay с RU-сервера", on_press=self.on_remove)
        self.status = toga.Label("", style=Pack(margin=(8, 0)))
        self.log_view = toga.MultilineTextInput(readonly=True, placeholder="Здесь будет журнал работы",
                                                style=Pack(height=360, margin=(4, 0, 24, 0)))
        return toga.Box(style=Pack(direction=COLUMN, margin=(0, 12)), children=[
            self._title("Российский сервер"),
            self._hint("Вход: к нему подключаются клиенты"),
            self._field("ru_host", "IPv4-адрес", "185.10.20.30"),
            self._field("ru_port", "SSH-порт", value="22"),
            self._field("ru_user", "Логин", value="root"),
            self._field("ru_pass", "Пароль", password=True),
            self._title("Зарубежный сервер"),
            self._hint("Выход: там стоит Amnezia"),
            self._field("de_host", "IPv6-адрес", "2a01:4f8:c0c:1234::2"),
            self._field("de_port", "SSH-порт", value="22"),
            self._field("de_user", "Логин", value="root"),
            self._field("de_pass", "Пароль", password=True),
            self._title("Порты"),
            self._field("ports", "Пусто = найти порты Amnezia автоматически", "51820/udp, 443/tcp"),
            self._field("ssh_fwd", "SSH-проброс для админского ключа (пусто = не нужен)", value="2222"),
            toga.Box(children=[self.btn_check, self.btn_setup], style=Pack(direction=ROW, gap=8, margin=(12, 0, 4, 0))),
            self.btn_remove,
            self.status,
            self.log_view,
        ])

    def _build_patch(self) -> toga.Box:
        self.cfg_in = toga.MultilineTextInput(placeholder="Вставь сюда ключ vpn://… или текст .conf",
                                              style=Pack(height=170))
        self.cfg_out = toga.MultilineTextInput(readonly=True, placeholder="Здесь появится новый ключ",
                                               style=Pack(height=170))
        self.patch_status = toga.Label("", style=Pack(margin=(6, 0)))
        return toga.Box(style=Pack(direction=COLUMN, margin=(0, 12, 24, 12)), children=[
            self._title("Переделать ключ клиента"),
            self._hint("В Amnezia: сервер → «Поделиться» → «Ключ Amnezia». "
                       "Скопируй ключ, вставь ниже и нажми «Преобразовать». "
                       "Готовый ключ скопируй и импортируй в Amnezia как новое подключение."),
            self._field("new_host", "Новый адрес (IPv4 RU-сервера)", "185.10.20.30"),
            self._field("old_host", "Старый адрес (пусто = определить самому)"),
            toga.Label("Исходный ключ", style=Pack(font_size=12, margin=(8, 0, 2, 0))),
            self.cfg_in,
            toga.Button("Преобразовать", on_press=self.on_patch, style=Pack(margin=(8, 0))),
            self.patch_status,
            toga.Label("Результат", style=Pack(font_size=12, margin=(4, 0, 2, 0))),
            self.cfg_out,
            toga.Box(children=[
                toga.Button("Копировать", on_press=self.on_copy, style=Pack(flex=1)),
                toga.Button("Поделиться", on_press=self.on_share, style=Pack(flex=1)),
            ], style=Pack(direction=ROW, gap=8, margin=(8, 0))),
        ])

    def _build_keys(self) -> toga.Box:
        self.btn_userkey = toga.Button("Создать обычный ключ", on_press=self.on_userkey, style=Pack(margin=(6, 0)))
        self.btn_adminkey = toga.Button("Создать админский ключ", on_press=self.on_adminkey, style=Pack(margin=(6, 0)))
        self.key_status = toga.Label("", style=Pack(margin=(6, 0)))
        self.key_out = toga.MultilineTextInput(readonly=True, placeholder="Здесь появится ключ",
                                               style=Pack(height=170))
        self.key_conf_btn = toga.Button("Показать как .conf", on_press=self.on_toggle_format, enabled=False,
                                        style=Pack(margin=(4, 0)))
        self.key_log = toga.MultilineTextInput(readonly=True, placeholder="Журнал", style=Pack(height=200))
        return toga.Box(style=Pack(direction=COLUMN, margin=(0, 12, 24, 12)), children=[
            self._hint("Ключи создаются прямо на зарубежном сервере и сразу содержат адрес RU-сервера. "
                       "Данные серверов берутся из раздела «Настройка». Каждому устройству — свой ключ."),
            self._title("Обычный ключ"),
            self._field("key_name", "Имя пользователя (так он будет называться в Amnezia)", value="Телефон"),
            self.btn_userkey,
            self._title("Админский ключ"),
            self._hint("Полный доступ к серверу из приложения Amnezia через SSH-проброс на RU-сервере. "
                       "В ключе root-пароль зарубежного сервера — никому его не отдавай. "
                       "Нужен порт SSH-проброса в «Настройке»."),
            self.btn_adminkey,
            self.key_status,
            self.key_out,
            self.key_conf_btn,
            toga.Box(children=[
                toga.Button("Копировать", on_press=self.on_copy_key, style=Pack(flex=1)),
                toga.Button("Поделиться", on_press=self.on_share_key, style=Pack(flex=1)),
            ], style=Pack(direction=ROW, gap=8, margin=(8, 0))),
            toga.Label("Журнал", style=Pack(font_size=12, margin=(8, 0, 2, 0))),
            self.key_log,
        ])

    def _show(self, which: str):
        self.scroll.content = self.views[which]
        for name, button in self.tabs.items():
            button.enabled = name != which

    def _val(self, key: str) -> str:
        return (self.inputs[key].value or "").strip()

    # ------------------------------------------------------------ settings --

    def _settings_file(self):
        return self.paths.data / "settings.json"

    def _load_settings(self):
        try:
            data = json.loads(self._settings_file().read_text("utf-8"))
        except Exception:
            return
        for key in SAVED_FIELDS:
            if data.get(key):
                self.inputs[key].value = data[key]
        if data.get("ru_host"):
            self.inputs["new_host"].value = data["ru_host"]

    def _save_settings(self):
        try:
            path = self._settings_file()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({k: self._val(k) for k in SAVED_FIELDS}, ensure_ascii=False), "utf-8")
        except Exception:
            pass  # пароли не сохраняются никогда

    # ------------------------------------------------------------- running --

    def _params(self) -> core.Params:
        def port(key: str, allow_empty: bool = False) -> int | None:
            raw = self._val(key)
            if allow_empty and not raw:
                return None
            try:
                value = int(raw or 22)
            except ValueError:
                raise core.RelayError("Порт должен быть числом") from None
            if not 1 <= value <= 65535:
                raise core.RelayError(f"Порт вне диапазона: {value}")
            return value

        return core.Params(
            ru=core.ServerCreds(self._val("ru_host"), port("ru_port"), self._val("ru_user") or "root",
                                self.inputs["ru_pass"].value or ""),
            foreign=core.ServerCreds(self._val("de_host"), port("de_port"), self._val("de_user") or "root",
                                     self.inputs["de_pass"].value or ""),
            ports=core.parse_ports(self._val("ports")),
            ssh_forward=port("ssh_fwd", allow_empty=True),
        )

    def log(self, msg: str, level: str = "info"):
        """Вызывается из рабочего потока — передаём в UI-поток."""
        self.loop.call_soon_threadsafe(self._append_log, msg, level)

    def _targets(self):
        """(журнал, строка статуса) текущей операции."""
        if self._active in ("userkey", "adminkey"):
            return self.key_log, self.key_status
        return self.log_view, self.status

    def _append_log(self, msg: str, level: str):
        box, status = self._targets()
        box.value = (box.value or "") + PREFIX.get(level, "  ") + msg + "\n"
        box.scroll_to_bottom()
        if level in ("step", "err"):
            status.text = msg.strip()

    def _set_busy(self, busy: bool):
        self.busy = busy
        for b in (self.btn_check, self.btn_setup, self.btn_remove, self.btn_userkey, self.btn_adminkey):
            b.enabled = not busy
        if busy:
            self._targets()[1].text = "Работаю… не закрывай приложение"

    async def _start(self, action: str):
        if self.busy:
            return
        try:
            params = self._params()
        except core.RelayError as e:
            await self.main_window.dialog(toga.ErrorDialog("Ошибка", str(e)))
            return
        if action == "remove" and not await self.main_window.dialog(toga.QuestionDialog(
                "Удаление", "Остановить и удалить relay с RU-сервера? Клиенты через него перестанут работать.")):
            return
        if action == "adminkey":
            if not params.ssh_forward:
                await self.main_window.dialog(toga.ErrorDialog(
                    "Нет SSH-проброса", "Впиши порт SSH-проброса в разделе «Настройка» (например 2222) "
                                        "и нажми «Настроить»."))
                return
            if not await self.main_window.dialog(toga.QuestionDialog(
                    "Админский ключ", "В ключе root-пароль зарубежного сервера: кто его получит, получит полный "
                                      "доступ к серверу. Импортируй его только в своё приложение Amnezia. Создать?")):
                return
        self._save_settings()
        self._active = action
        self._targets()[0].value = ""
        self._set_busy(True)
        threading.Thread(target=self._worker, args=(action, params, self._val("key_name")), daemon=True).start()

    def _worker(self, action: str, params: core.Params, key_name: str):
        result = None
        try:
            if action == "check":
                core.run_check(params, self.log)
            elif action == "setup":
                result, _ = core.run_setup(params, self.log)
            elif action == "remove":
                core.run_remove(params, self.log)
            elif action == "userkey":
                result = keys.create_user_key(params, key_name, self.log)
            elif action == "adminkey":
                result = keys.build_admin_key(params, params.ssh_forward, self.log)
        except core.RelayError as e:
            self.log(str(e), "err")
        except Exception as e:
            self.log(f"Неожиданная ошибка: {e}", "err")
            self.log(traceback.format_exc(), "info")
        finally:
            self.loop.call_soon_threadsafe(self._done, action, result)

    def _done(self, action: str, result):
        status = self._targets()[1]
        self._set_busy(False)
        if not result:
            if status.text.startswith("Работаю"):
                status.text = "Relay удалён" if action == "remove" else "Готово"
            return
        if action == "setup":
            status.text = f"Готово. Новый адрес для клиентов: {result}"
            self.inputs["new_host"].value = result
            self.loop.create_task(self.main_window.dialog(toga.InfoDialog(
                "Готово", f"Relay настроен.\nНовый адрес для клиентов: {result}\n\n"
                          "Новые ключи для устройств выдаются в разделе «Ключи».")))
        elif action == "userkey":
            self.user_key = result
            self.key_out.value = result.vpn
            self.key_conf_btn.enabled = True
            self.key_conf_btn.text = "Показать как .conf"
            status.text = f"✔ Ключ «{result.name}» готов ({result.ip})"
        elif action == "adminkey":
            self.user_key = None
            self.key_out.value = result
            self.key_conf_btn.enabled = False
            status.text = "✔ Админский ключ готов — никому его не отдавай"

    async def on_check(self, widget, **kwargs):
        await self._start("check")

    async def on_setup(self, widget, **kwargs):
        await self._start("setup")

    async def on_remove(self, widget, **kwargs):
        await self._start("remove")

    async def on_userkey(self, widget, **kwargs):
        await self._start("userkey")

    async def on_adminkey(self, widget, **kwargs):
        await self._start("adminkey")

    async def on_toggle_format(self, widget, **kwargs):
        if not self.user_key:
            return
        if self.key_out.value == self.user_key.vpn:
            self.key_out.value = self.user_key.conf
            widget.text = "Показать как vpn://"
        else:
            self.key_out.value = self.user_key.vpn
            widget.text = "Показать как .conf"

    async def on_copy_key(self, widget, **kwargs):
        self.key_status.text = self._copy_text(self.key_out.value)

    async def on_share_key(self, widget, **kwargs):
        msg = self._share_text(self.key_out.value)
        if msg:
            self.key_status.text = msg

    # --------------------------------------------------------------- patch --

    async def on_patch(self, widget, **kwargs):
        src = (self.cfg_in.value or "").strip()
        if not src:
            await self.main_window.dialog(toga.InfoDialog("Пусто", "Вставь ключ vpn:// или текст .conf"))
            return
        try:
            new = core.norm_v4(self._val("new_host"))
            res, kind, old, n = patch_any(src, new, self._val("old_host") or None)
        except (PatchError, core.RelayError) as e:
            await self.main_window.dialog(toga.ErrorDialog("Ошибка", str(e)))
            return
        self.cfg_out.value = res
        self.patch_status.text = f"✔ {old} → {new} (замен: {n}, формат: {kind})"

    # Буфер обмена и «Поделиться» — через Android API (Chaquopy). В Toga своего буфера нет.

    def _activity(self):
        native = getattr(self._impl, "native", None)
        if native is not None and hasattr(native, "getSystemService"):
            return native
        from java import jclass
        return jclass("org.beeware.android.MainActivity").singletonThis

    def _copy_text(self, text: str | None) -> str:
        """Копирует в буфер обмена Android; возвращает текст для строки статуса."""
        text = (text or "").strip()
        if not text:
            return ""
        try:
            from java import jclass
            context = jclass("android.content.Context")
            clip_data = jclass("android.content.ClipData")
            manager = self._activity().getSystemService(context.CLIPBOARD_SERVICE)
            manager.setPrimaryClip(clip_data.newPlainText("Relay Connect", text))
            return "✔ Ключ скопирован в буфер обмена"
        except Exception:
            return "Не удалось скопировать: выдели текст и скопируй вручную"

    def _share_text(self, text: str | None) -> str:
        """Открывает «Поделиться» Android; возвращает текст ошибки или пустую строку."""
        text = (text or "").strip()
        if not text:
            return ""
        try:
            from android.content import Intent
            intent = Intent(Intent.ACTION_SEND)
            intent.setType("text/plain")
            intent.putExtra(Intent.EXTRA_TEXT, text)
            chooser = Intent.createChooser(intent, "Поделиться ключом")
            try:
                self._impl.start_activity(chooser, on_complete=lambda *a, **k: None)
            except Exception:
                self._activity().startActivity(chooser)
            return ""
        except Exception:
            return "«Поделиться» доступно только на Android; скопируй ключ вручную"

    async def on_copy(self, widget, **kwargs):
        self.patch_status.text = self._copy_text(self.cfg_out.value)

    async def on_share(self, widget, **kwargs):
        msg = self._share_text(self.cfg_out.value)
        if msg:
            self.patch_status.text = msg


def main():
    return RelayConnect("Relay Connect", "ru.relayconnect.relay_connect")
