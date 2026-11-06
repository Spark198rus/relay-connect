"""
Relay Connect — настольная версия (Windows, macOS, Linux), tkinter.

Вводишь IPv4 российского сервера, IPv6 зарубежного, root-пароли —
программа сама настраивает пересылку RU(IPv4) → DE(IPv6) для Amnezia
и выдаёт новые ключи (обычные и админские) уже с адресом RU-сервера.
Android-версия лежит в src/relay_connect/mobile.py и использует то же ядро.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import tkinter as tk
import traceback
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

# общее ядро лежит в src/relay_connect (при сборке PyInstaller получает --paths src)
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from relay_connect import keys  # noqa: E402
from relay_connect import relay_core as core  # noqa: E402
from relay_connect.config_patch import PatchError, patch_any  # noqa: E402

APP_TITLE = "Relay Connect — обход блокировки IPv4 через RU-сервер"
COLORS = {"info": "#222222", "ok": "#1a7f37", "warn": "#9a6700", "err": "#cf222e", "step": "#0550ae"}
PREFIX = {"ok": "✔ ", "warn": "⚠ ", "err": "✖ ", "step": "\n▶ "}
ADMIN_WARNING = (
    "В админском ключе лежит root-пароль зарубежного сервера. Кто получит ключ, "
    "получит полный доступ к серверу. Не пересылай его в чаты и никому не отдавай.\n\n"
    "Импортируй его только в своё приложение Amnezia. Создать ключ?")


def _settings_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "relay-connect" / "settings.json"


SETTINGS = _settings_path()
# моноширинный шрифт для логов: на каждой системе свой
MONO = {"win32": ("Consolas", 9), "darwin": ("Menlo", 11)}.get(sys.platform, ("DejaVu Sans Mono", 9))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("880x740")
        self.minsize(720, 600)
        self.q: queue.Queue = queue.Queue()
        self.busy = False
        self.buttons: list[ttk.Button] = []
        self._active_log: scrolledtext.ScrolledText | None = None
        self._user_key: keys.UserKey | None = None

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.nb = nb
        self._build_setup(nb)
        self._build_keys(nb)
        self._build_patch(nb)
        self._load_settings()
        self.after(100, self._drain)

    # ------------------------------------------------------------------ UI --

    def _field(self, parent, row, label, var, show=None, width=34, hint=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=6, pady=3)
        e = ttk.Entry(parent, textvariable=var, width=width, show=show)
        e.grid(row=row, column=1, sticky="we", padx=6, pady=3)
        if hint:
            ttk.Label(parent, text=hint, foreground="#666").grid(row=row, column=2, sticky="w", padx=6)
        return e

    def _log_widget(self, parent, height: int) -> scrolledtext.ScrolledText:
        box = scrolledtext.ScrolledText(parent, height=height, wrap="word", font=MONO)
        for lvl, col in COLORS.items():
            box.tag_config(lvl, foreground=col)
        box.tag_config("step", foreground=COLORS["step"], font=(*MONO, "bold"))
        box.configure(state="disabled")
        return box

    def _button(self, parent, text, action) -> ttk.Button:
        b = ttk.Button(parent, text=text, command=lambda: self._start(action))
        self.buttons.append(b)
        return b

    def _build_setup(self, nb):
        f = ttk.Frame(nb)
        nb.add(f, text="  Настройка  ")
        f.columnconfigure(0, weight=1)

        self.v = {k: tk.StringVar() for k in (
            "ru_host", "ru_port", "ru_user", "ru_pass",
            "de_host", "de_port", "de_user", "de_pass", "ports", "ssh_fwd")}
        self.v["ru_port"].set("22"); self.v["de_port"].set("22")
        self.v["ru_user"].set("root"); self.v["de_user"].set("root")
        self.v["ssh_fwd"].set("2222")

        ru = ttk.LabelFrame(f, text=" Российский сервер (вход, к нему подключаются клиенты) ")
        ru.grid(row=0, column=0, sticky="we", padx=4, pady=4)
        ru.columnconfigure(1, weight=1)
        self._field(ru, 0, "IPv4-адрес", self.v["ru_host"], hint="например 185.10.20.30")
        self._field(ru, 1, "SSH-порт", self.v["ru_port"], width=8)
        self._field(ru, 2, "Логин", self.v["ru_user"], width=16)
        self._field(ru, 3, "Пароль", self.v["ru_pass"], show="•")

        de = ttk.LabelFrame(f, text=" Зарубежный сервер (выход, там стоит Amnezia) ")
        de.grid(row=1, column=0, sticky="we", padx=4, pady=4)
        de.columnconfigure(1, weight=1)
        self._field(de, 0, "IPv6-адрес", self.v["de_host"], hint="например 2a01:4f8:c0c:1234::2")
        self._field(de, 1, "SSH-порт", self.v["de_port"], width=8)
        self._field(de, 2, "Логин", self.v["de_user"], width=16)
        self._field(de, 3, "Пароль", self.v["de_pass"], show="•")

        pf = ttk.LabelFrame(f, text=" Порты ")
        pf.grid(row=2, column=0, sticky="we", padx=4, pady=4)
        pf.columnconfigure(1, weight=1)
        self._field(pf, 0, "Порты Amnezia", self.v["ports"],
                    hint="пусто = найти сами;\nили вручную: 51820/udp, 443/tcp")
        self._field(pf, 1, "SSH-проброс", self.v["ssh_fwd"], width=8,
                    hint="порт на RU-сервере для админского ключа;\nпусто = не нужен")

        bf = ttk.Frame(f)
        bf.grid(row=3, column=0, sticky="we", padx=4, pady=6)
        for b in (self._button(bf, "1. Проверить", "check"),
                  self._button(bf, "2. Настроить", "setup"),
                  self._button(bf, "Удалить relay с RU-сервера", "remove")):
            b.pack(side="left", padx=4)
        self.progress = ttk.Progressbar(bf, mode="indeterminate", length=140)
        self.progress.pack(side="right", padx=4)

        self.log_box = self._log_widget(f, 18)
        self.log_box.grid(row=4, column=0, sticky="nsew", padx=4, pady=4)
        f.rowconfigure(4, weight=1)

    def _build_keys(self, nb):
        f = ttk.Frame(nb)
        nb.add(f, text="  Ключи  ")
        f.columnconfigure(0, weight=1)
        ttk.Label(f, wraplength=820, justify="left", text=(
            "Новые ключи создаются прямо на зарубежном сервере (через RU-сервер) и сразу содержат адрес "
            "RU-сервера. Данные серверов берутся с вкладки «Настройка». Каждому устройству — свой ключ."
        )).grid(row=0, column=0, sticky="w", padx=6, pady=6)

        uf = ttk.LabelFrame(f, text=" Обычный ключ — для нового устройства ")
        uf.grid(row=1, column=0, sticky="we", padx=4, pady=4)
        uf.columnconfigure(1, weight=1)
        self.key_name = tk.StringVar(value="Телефон")
        self._field(uf, 0, "Имя пользователя", self.key_name, width=28, hint="так он будет называться в Amnezia")
        self._button(uf, "Создать обычный ключ", "userkey").grid(row=1, column=1, sticky="w", padx=6, pady=4)

        af = ttk.LabelFrame(f, text=" Админский ключ — полный доступ к серверу из приложения Amnezia ")
        af.grid(row=2, column=0, sticky="we", padx=4, pady=4)
        ttk.Label(af, wraplength=800, justify="left", foreground="#9a6700", text=(
            "Приложение будет управлять сервером через SSH-проброс на RU-сервере, а все ключи, которые оно "
            "создаст через «Поделиться», сразу будут с адресом RU-сервера. Внутри ключа root-пароль "
            "зарубежного сервера: никому его не отдавай. Нужен включённый SSH-проброс (вкладка «Настройка»)."
        )).pack(anchor="w", padx=6, pady=(4, 2))
        self._button(af, "Создать админский ключ", "adminkey").pack(anchor="w", padx=6, pady=4)

        of = ttk.LabelFrame(f, text=" Результат ")
        of.grid(row=3, column=0, sticky="nsew", padx=4, pady=4)
        of.columnconfigure(0, weight=1)
        of.rowconfigure(1, weight=1)
        top = ttk.Frame(of)
        top.grid(row=0, column=0, sticky="we", padx=4, pady=2)
        self.key_format = tk.StringVar(value="vpn")
        self.fmt_vpn = ttk.Radiobutton(top, text="Ключ vpn://", value="vpn", variable=self.key_format,
                                       command=self._show_key)
        self.fmt_conf = ttk.Radiobutton(top, text="Файл .conf", value="conf", variable=self.key_format,
                                        command=self._show_key)
        self.fmt_vpn.pack(side="left")
        self.fmt_conf.pack(side="left", padx=8)
        ttk.Button(top, text="Копировать", command=lambda: self._copy(self.key_out, self.key_status)).pack(
            side="left", padx=(16, 4))
        ttk.Button(top, text="Сохранить…", command=self._save_key).pack(side="left")
        self.key_status = ttk.Label(top, text="")
        self.key_status.pack(side="left", padx=10)
        self.key_out = scrolledtext.ScrolledText(of, height=8, wrap="char", font=MONO)
        self.key_out.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)

        self.key_log = self._log_widget(f, 8)
        self.key_log.grid(row=4, column=0, sticky="nsew", padx=4, pady=4)
        f.rowconfigure(3, weight=1)
        f.rowconfigure(4, weight=1)
        self._key_kind = "user"

    def _build_patch(self, nb):
        f = ttk.Frame(nb)
        nb.add(f, text="  Конфиг клиента  ")
        f.columnconfigure(0, weight=1)

        ttk.Label(f, wraplength=800, justify="left", text=(
            "Для уже существующих ключей. В приложении Amnezia открой сервер → «Поделиться» → «Ключ Amnezia» "
            "(vpn://…) или «Нативный формат AmneziaWG» (.conf). Вставь сюда — программа заменит адрес "
            "зарубежного сервера на адрес RU-сервера. Потом импортируй результат в Amnezia "
            "как новое подключение.")).grid(row=0, column=0, sticky="w", padx=6, pady=6)

        top = ttk.Frame(f)
        top.grid(row=1, column=0, sticky="we", padx=6)
        ttk.Button(top, text="Открыть файл…", command=self._open_cfg).pack(side="left")
        ttk.Label(top, text="   Новый адрес (IPv4 RU-сервера):").pack(side="left")
        self.new_host = tk.StringVar()
        ttk.Entry(top, textvariable=self.new_host, width=18).pack(side="left", padx=4)
        ttk.Label(top, text="  Старый адрес:").pack(side="left")
        self.old_host = tk.StringVar()
        ttk.Entry(top, textvariable=self.old_host, width=18).pack(side="left", padx=4)
        ttk.Label(top, text="(пусто = авто)", foreground="#666").pack(side="left")

        ttk.Label(f, text="Исходный конфиг / ключ:").grid(row=2, column=0, sticky="w", padx=6, pady=(8, 0))
        self.cfg_in = scrolledtext.ScrolledText(f, height=10, wrap="char", font=MONO)
        self.cfg_in.grid(row=3, column=0, sticky="nsew", padx=6)

        mid = ttk.Frame(f)
        mid.grid(row=4, column=0, sticky="we", padx=6, pady=6)
        ttk.Button(mid, text="Преобразовать ↓", command=self._patch).pack(side="left")
        ttk.Button(mid, text="Копировать результат",
                   command=lambda: self._copy(self.cfg_out, self.patch_status)).pack(side="left", padx=6)
        ttk.Button(mid, text="Сохранить…", command=self._save_out).pack(side="left")
        self.patch_status = ttk.Label(mid, text="")
        self.patch_status.pack(side="left", padx=10)

        ttk.Label(f, text="Результат:").grid(row=5, column=0, sticky="w", padx=6)
        self.cfg_out = scrolledtext.ScrolledText(f, height=10, wrap="char", font=MONO)
        self.cfg_out.grid(row=6, column=0, sticky="nsew", padx=6, pady=(0, 6))
        f.rowconfigure(3, weight=1)
        f.rowconfigure(6, weight=1)
        self._out_kind = "conf"

    # ------------------------------------------------------------ settings --

    def _load_settings(self):
        try:
            data = json.loads(SETTINGS.read_text("utf-8"))
        except Exception:
            return
        for k, val in data.items():
            if k in self.v and not k.endswith("_pass"):
                self.v[k].set(val)
        self.new_host.set(data.get("ru_host", ""))

    def _save_settings(self):
        try:
            SETTINGS.parent.mkdir(parents=True, exist_ok=True)
            data = {k: var.get() for k, var in self.v.items() if not k.endswith("_pass")}
            SETTINGS.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
        except Exception:
            pass  # пароли никогда не сохраняются

    # ------------------------------------------------------------- running --

    def log(self, msg: str, level: str = "info"):
        self.q.put(("log", self._active_log, msg, level))

    def _write_log(self, box, msg: str, level: str):
        box.configure(state="normal")
        box.insert("end", PREFIX.get(level, "  ") + msg + "\n", level)
        box.see("end")
        box.configure(state="disabled")

    def _drain(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item[0] == "log":
                    _, box, msg, level = item
                    self._write_log(box or self.log_box, msg, level)
                    if box is self.key_log and level in ("step", "err", "ok"):
                        self.key_status.configure(text=msg.strip()[:80], foreground=COLORS[level])
                elif item[0] == "done":
                    self._done(item[1], item[2])
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _done(self, action: str, result):
        self._set_busy(False)
        if not result:
            return
        if action == "setup":
            self.new_host.set(result)
            messagebox.showinfo("Готово", f"Relay настроен.\nНовый адрес для клиентов: {result}\n\n"
                                "Новые ключи для устройств выдаются на вкладке «Ключи».")
            self.nb.select(1)
        elif action == "userkey":
            self._user_key = result
            self._key_kind = "user"
            self.fmt_vpn.configure(state="normal")
            self.fmt_conf.configure(state="normal")
            self._show_key()
            self.key_status.configure(text=f"✔ Ключ «{result.name}» готов ({result.ip})", foreground=COLORS["ok"])
        elif action == "adminkey":
            self._key_kind = "admin"
            self.key_format.set("vpn")
            self.fmt_conf.configure(state="disabled")
            self.key_out.delete("1.0", "end")
            self.key_out.insert("1.0", result)
            self.key_status.configure(text="✔ Админский ключ готов — никому его не отдавай", foreground=COLORS["warn"])

    def _set_busy(self, busy: bool):
        self.busy = busy
        for b in self.buttons:
            b.configure(state="disabled" if busy else "normal")
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _params(self) -> core.Params:
        def port(k, default=22, allow_empty=False):
            raw = self.v[k].get().strip()
            if allow_empty and not raw:
                return None
            try:
                value = int(raw or default)
            except ValueError:
                raise core.RelayError("Порт должен быть числом") from None
            if not 1 <= value <= 65535:
                raise core.RelayError(f"Порт вне диапазона: {value}")
            return value
        return core.Params(
            ru=core.ServerCreds(self.v["ru_host"].get().strip(), port("ru_port"),
                                self.v["ru_user"].get().strip() or "root", self.v["ru_pass"].get()),
            foreign=core.ServerCreds(self.v["de_host"].get().strip(), port("de_port"),
                                     self.v["de_user"].get().strip() or "root", self.v["de_pass"].get()),
            ports=core.parse_ports(self.v["ports"].get()),
            ssh_forward=port("ssh_fwd", allow_empty=True),
        )

    def _start(self, action: str):
        if self.busy:
            return
        try:
            p = self._params()
        except core.RelayError as e:
            messagebox.showerror("Ошибка", str(e))
            return
        if action == "remove" and not messagebox.askyesno(
                "Удаление", "Остановить и удалить relay с RU-сервера? Клиенты через него перестанут работать."):
            return
        if action == "adminkey":
            if not p.ssh_forward:
                messagebox.showerror("Нет SSH-проброса", "Впиши порт в поле «SSH-проброс» на вкладке «Настройка» "
                                                         "(например 2222) и нажми «Настроить».")
                return
            if not messagebox.askyesno("Админский ключ", ADMIN_WARNING, icon="warning"):
                return
        self._save_settings()
        box = self.key_log if action in ("userkey", "adminkey") else self.log_box
        self._active_log = box
        box.configure(state="normal"); box.delete("1.0", "end"); box.configure(state="disabled")
        self._set_busy(True)
        threading.Thread(target=self._worker, args=(action, p, self.key_name.get()), daemon=True).start()

    def _worker(self, action: str, p: core.Params, key_name: str):
        result = None
        try:
            if action == "check":
                core.run_check(p, self.log)
            elif action == "setup":
                result, _ = core.run_setup(p, self.log)
            elif action == "remove":
                core.run_remove(p, self.log)
            elif action == "userkey":
                result = keys.create_user_key(p, key_name, self.log)
            elif action == "adminkey":
                result = keys.build_admin_key(p, p.ssh_forward, self.log)
        except core.RelayError as e:
            self.log(str(e), "err")
        except Exception as e:
            self.log(f"Неожиданная ошибка: {e}", "err")
            self.log(traceback.format_exc(), "info")
        finally:
            self.q.put(("done", action, result))

    # ---------------------------------------------------------------- keys --

    def _show_key(self):
        if self._key_kind != "user" or not self._user_key:
            return
        text = self._user_key.vpn if self.key_format.get() == "vpn" else self._user_key.conf
        self.key_out.delete("1.0", "end")
        self.key_out.insert("1.0", text)

    def _save_key(self):
        out = self.key_out.get("1.0", "end").strip()
        if not out:
            return
        is_conf = self._key_kind == "user" and self.key_format.get() == "conf"
        ext = ".conf" if is_conf else ".vpn"
        name = (self._user_key.name if self._key_kind == "user" and self._user_key else "admin")
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name) or "key"
        path = filedialog.asksaveasfilename(defaultextension=ext, initialfile=f"{safe}{ext}")
        if path:
            Path(path).write_text(out + "\n", "utf-8")

    def _copy(self, box, status):
        out = box.get("1.0", "end").strip()
        if out:
            self.clipboard_clear()
            self.clipboard_append(out)
            status.configure(text="Скопировано в буфер обмена", foreground=COLORS["ok"])

    # --------------------------------------------------------------- patch --

    def _open_cfg(self):
        path = filedialog.askopenfilename(filetypes=[("Конфиги", "*.conf *.vpn *.txt"), ("Все файлы", "*.*")])
        if not path:
            return
        try:
            text = Path(path).read_text("utf-8")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return
        self.cfg_in.delete("1.0", "end")
        self.cfg_in.insert("1.0", text)

    def _patch(self):
        src = self.cfg_in.get("1.0", "end").strip()
        new = self.new_host.get().strip()
        if not src:
            messagebox.showwarning("Пусто", "Вставь ключ vpn:// или содержимое .conf")
            return
        try:
            new = core.norm_v4(new)
            res, kind, old, n = patch_any(src, new, self.old_host.get().strip() or None)
        except (PatchError, core.RelayError) as e:
            messagebox.showerror("Ошибка", str(e))
            return
        self._out_kind = kind
        self.cfg_out.delete("1.0", "end")
        self.cfg_out.insert("1.0", res)
        self.patch_status.configure(text=f"✔ {old} → {new}  (замен: {n}, формат: {kind})", foreground=COLORS["ok"])

    def _save_out(self):
        out = self.cfg_out.get("1.0", "end").strip()
        if not out:
            return
        ext = ".vpn" if self._out_kind == "vpn" else ".conf"
        path = filedialog.asksaveasfilename(defaultextension=ext, initialfile=f"relay{ext}")
        if path:
            Path(path).write_text(out + "\n", "utf-8")


if __name__ == "__main__":
    App().mainloop()
