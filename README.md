# Relay Connect

Обход блокировки IPv4 зарубежного VPN-сервера через российский VPS.

```
Клиент AmneziaWG ──IPv4──► RU-сервер ──(realm)──IPv6──► Зарубежный сервер (AmneziaWG)
```

РКН блокирует IPv4 зарубежных серверов, но их IPv6 обычно живой. Клиенты
подключаются к российскому серверу, а тот пересылает
пакеты через IPv6 зарубежного. Шифрование остаётся сквозным: RU-сервер видит только
зашифрованный трафик AmneziaWG и ключей не знает.

Полная документация и FAQ по ошибкам: [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md)
(то же в PDF: `docs/Relay-Connect-documentation.pdf`).

Программа сама определяет, как на зарубежном сервере стоит AmneziaWG:

| Что на сервере | Что делает программа |
|---|---|
| AmneziaWG от скрипта [amneziawg-installer](https://github.com/bivlked/amneziawg-installer) | прописывает в его настройки адрес RU-сервера, чтобы все ключи клиентов вели на relay |
| Amnezia, поставленная приложением Amnezia (контейнеры в docker) | берёт порты контейнеров; новые ключи и админский ключ собирает сама |
| ничего | **спрашивает** и ставит AmneziaWG скриптом amneziawg-installer, потом настраивает relay |

Уже установленный AmneziaWG программа **не переустанавливает**.
На RU-сервере ставится только `realm`, маленький форвардер TCP/UDP, как systemd-сервис.
Настройка проводится **один раз**, после этого можно использовать обычные приложения AmneziaWG и Amnezia VPN.

## Что нужно

| | Российский VPS | Зарубежный VPS |
|---|---|---|
| IPv4 | да (к нему подключаются клиенты) | заблокирован, не важно |
| IPv6 | **да** (через него идёт трафик на зарубежный) | **да** |
| Доступ | root + пароль | root + пароль |
| ОС | Linux с systemd (Ubuntu/Debian) | любая с systemd; если ставить AmneziaWG программой — Ubuntu 24.04/26.04 или Debian 12/13 |
| AmneziaWG | не нужен | amneziawg-installer (с `--allow-ipv6`, см. ниже), Amnezia в docker или ничего |

При покупке RU-VPS проверьте, что хостер выдаёт IPv6: многие дают его только по
запросу или за отдельную плату.

### Если AmneziaWG ставили сами через amneziawg-installer

По умолчанию amneziawg-installer **выключает IPv6** на сервере, а relay ходит на него именно по IPv6.
Если программа ставит AmneziaWG сама, она передаёт нужный флаг. Если ставите вручную — с флагом `--allow-ipv6`:

```bash
bash install_amneziawg.sh --allow-ipv6
```

Если сервер уже поставлен без флага, верните IPv6 (через консоль хостера или по SSH на IPv4
из сети, где он не заблокирован) и перезагрузите сервер:

```bash
sed -i -E 's/^(net\.ipv6\.conf\.(all|default|lo)\.disable_ipv6 *= *)1/\10/' /etc/sysctl.d/99-amneziawg-*.conf
sed -i 's/^export DISABLE_IPV6=.*/export DISABLE_IPV6=0/' /root/awg/awgsetup_cfg.init
reboot
```

После перезагрузки `ip -6 addr show scope global` должен показать IPv6-адрес.

## Как пользоваться

1. Запустить программу для своей системы (см. «Платформы» ниже), или из исходников `python app.py`
   (для установки зависимостей выполнить `pip install -r requirements.txt`).
2. На вкладке **Настройка** ввести IPv4 RU-сервера, IPv6 зарубежного, логины и пароли.
   Если поле «Порты» оставить пустым, программа найдёт порты сама: из `/etc/amnezia/amneziawg/awg0.conf`
   (amneziawg-installer) или из `docker ps` (Amnezia в docker).
3. Нажать кнопку **Проверить**: выполнятся все необходимые проверки, на серверах ничего не меняется.
4. Нажать кнопку **Настроить**: ставит и запускает relay, в конце прогоняет тестовый пакет.
   Если AmneziaWG на зарубежном сервере нет, программа спросит, поставить ли его (подробнее — ниже).
5. На вкладке **Ключи** взять ключи:
   - amneziawg-installer: «Показать ключ существующего» — для клиентов, которые уже были (их файлы программа
     перевыпустила с адресом RU-сервера), «Создать нового клиента» — для новых устройств;
   - Amnezia в docker: «Создать нового клиента» или «Создать админский ключ» (приложение Amnezia будет управлять
     сервером через RU-сервер; нужен SSH-проброс).

   Ключи импортировать на устройствах заново.
6. Вкладка **Конфиг клиента** меняет адрес в ключе, который уже есть на руках (для Amnezia в docker —
   это единственный способ сохранить старые ключи).

### Установка AmneziaWG программой

Если на зарубежном сервере нет ни amneziawg-installer, ни контейнеров Amnezia, «Настроить» останавливается
до любых изменений и спрашивает, ставить ли AmneziaWG. После «Да» программа:
- проверяет ОС (Ubuntu 24.04/26.04 или Debian 12/13);
- скачивает `install_amneziawg.sh` с GitHub в `/root` (если сервер не может — качает на ПК и заливает по SFTP)
  и запускает его в фоне: `--yes --no-color --allow-ipv6 --keep-packages --endpoint=<IPv4 RU-сервера>`;
- показывает лог установщика; установщик дважды перезагружает сервер — программа ждёт, переподключается
  через RU-сервер и запускает его снова, пока он не закончит;
- после установки сама продолжает настройку relay.

Установка занимает 10–30 минут. Установщик обновляет пакеты системы, включает фаервол UFW (входящие закрыты,
кроме SSH и порта AmneziaWG) и ставит Fail2Ban. Если на сервере работает что-то ещё, UFW может закрыть к нему
доступ. Если установка прервалась, нажмите «Настроить» ещё раз: она продолжится с того же шага.
Вывод установщика: `/root/relay-connect-awg-install.out`, его лог: `/root/awg/install_amneziawg.log`.

Пароли никуда не сохраняются. В `%APPDATA%\relay-connect\settings.json` запоминаются
только адреса, порты и логины.

## Что именно делает программа

**Зарубежный сервер** (SSH к нему идёт через RU-сервер по IPv6, так заодно проверяется связность):
- проверяет, что указанный IPv6 есть на интерфейсе;
- определяет, как стоит AmneziaWG. amneziawg-installer: порт из `ListenPort` в
  `/etc/amnezia/amneziawg/awg0.conf`, клиенты, сервис `awg-quick@awg0`. Amnezia в docker: порты контейнеров
  `amnezia-*` из `docker ps`. Ничего — предлагает установить (см. выше);
- проверяет, что порт слушается по IPv6 (`ss`). Если нет, ставит мост
  `realm [IPv6]:порт → 127.0.0.1:порт` (сервис `relay-connect@bridge-udp`);
- открывает порт для IPv6 в ufw/firewalld/ip6tables, если фаервол закрыт (правило установщика в UFW не трогает).

Только для amneziawg-installer:
- если установщик выключил IPv6 до следующей перезагрузки (`disable_ipv6 = 1` в sysctl), меняет на `0`
  и пишет `DISABLE_IPV6=0` в `/root/awg/awgsetup_cfg.init`;
- прописывает IPv4 RU-сервера в `AWG_ENDPOINT` в `/root/awg/awgsetup_cfg.init` (копия до изменения:
  `awgsetup_cfg.init.relay-connect.bak`) и перевыпускает файлы клиентов: `manage_amneziawg.sh regen`.
  После этого ключи, которые выдаёт установщик, сами ведут на RU-сервер.

В контейнерах Amnezia программа ничего не меняет, пока не создаётся новый ключ (тогда пользователь
дописывается в конфиг AmneziaWG контейнера, копия: `awg0.conf.relay-connect.bak`).

**RU-сервер:**
- проверяет IPv6-маршрут до зарубежного сервера и что порты свободны;
- ставит `realm v2.9.6` в `/usr/local/bin/realm`. Если сервер не может скачать его с GitHub,
  файл качается на ПК и заливается по SFTP;
- конфиги лежат в `/etc/relay-connect/udp.toml` и `tcp.toml`, сервисы называются
  `relay-connect@udp` и `relay-connect@tcp` (DynamicUser, без root, автоперезапуск);
- увеличивает UDP-буферы (`/etc/sysctl.d/99-relay-connect.conf`);
- открывает порты в фаерволе;
- проверка: шлёт UDP-пакет в relay и ловит его `tcpdump`-ом на зарубежном сервере.

## Диагностика вручную (на RU-сервере)

```bash
systemctl status relay-connect@udp
journalctl -u relay-connect@udp -n 50
cat /etc/relay-connect/udp.toml
ping -6 -c 3 <IPv6 зарубежного>
```

## Частые проблемы

- **«нет IPv6-маршрута»**: у RU-VPS не включён IPv6. Включи его в панели хостера.
- **Тестовый пакет не дошёл**: у зарубежного хостера может быть внешний фаервол в
  панели (например, Hetzner Cloud Firewall). Открой там UDP-порт AmneziaWG для IPv6.
- **Ключ подключается, но интернета нет**: проверь, что импортировал именно
  новый ключ, где адрес = IPv4 RU-сервера.
- **«Показать ключ существующего» не работает с Amnezia в docker**: там сервер не хранит ключи пользователей.
  Возьми ключ в приложении Amnezia («Поделиться») и поменяй адрес на вкладке «Конфиг клиента».
- **Установка AmneziaWG остановилась с ошибкой**: программа показывает последние строки лога установщика.
  Исправь причину и нажми «Настроить» ещё раз — установка продолжится с того же шага.
- **Если заблокируют и IPv6**: поменяй IPv6 у хостера (обычно выдают /64, адрес
  можно сменить) и снова нажми «Настроить».

## Удаление

Кнопка «Удалить relay с RU-сервера» останавливает сервисы и удаляет realm и конфиги.
Правила фаервола остаются. На зарубежном сервере вручную:
- мост, если ставился: `systemctl disable --now relay-connect@bridge-udp relay-connect@bridge-tcp`;
- для amneziawg-installer вернуть в ключи прямой адрес сервера:
  `sed -i "s/^export AWG_ENDPOINT=.*/export AWG_ENDPOINT=''/" /root/awg/awgsetup_cfg.init && bash /root/awg/manage_amneziawg.sh regen`.

## Платформы

| Система | Файл | Как запустить |
|---|---|---|
| Windows 10/11 | `RelayConnect-windows.exe` | двойной клик; SmartScreen: «Подробнее» → «Выполнить в любом случае» |
| macOS (Apple Silicon) | `RelayConnect-macos-arm64.zip` | распаковать, правый клик по `RelayConnect.app` → «Открыть»; если macOS не даёт: `xattr -dr com.apple.quarantine RelayConnect.app` |
| Linux x86_64 | `RelayConnect-linux-x86_64.tar.gz` | `tar xzf RelayConnect-linux-x86_64.tar.gz && ./RelayConnect` (нужен графический сеанс) |
| Android 7+ (64-bit) | `RelayConnect-android.apk` | скопировать на телефон, открыть, разрешить установку из неизвестных источников |

Функции везде одинаковые. На Android ключ клиента вставляется из буфера обмена, а результат копируется кнопкой
«Копировать» или отправляется кнопкой «Поделиться» (открыть файл с ключом там нельзя, только вставить текст).

Для macOS GitHub собирает версию только под Apple Silicon. На Mac с Intel запускай из исходников:
`python3 app.py`. 32-битные Android-телефоны не поддерживаются (Python 3.12 на Android только 64-битный).

## Сборка

**Автоматически, через GitHub Actions** ([.github/workflows/build.yml](.github/workflows/build.yml)).
Залей проект в свой репозиторий на GitHub:
- при каждом пуше в `main` собираются все четыре версии; файлы лежат во вкладке **Actions → запуск → Artifacts**;
- при пуше тега (`git tag v1.0.0 && git push origin v1.0.0`) создаётся **Release** со всеми файлами.

Если сборка Android упала, в артефактах запуска будут логи Briefcase (`briefcase-logs`).

**Вручную:**
- Windows: `build.bat` → `dist\RelayConnect.exe`
- macOS / Linux: `./build.sh` → `dist/RelayConnect.app` или `dist/RelayConnect`
- Android: `pip install briefcase`, затем `briefcase create android`, `briefcase build android`,
  `briefcase package android -p debug-apk` (Briefcase сам скачает JDK и Android SDK, около 2 ГБ).

## Структура

```
app.py                      настольная версия (tkinter): Windows, macOS, Linux
src/relay_connect/
    relay_core.py           ядро: SSH, проверки, установка realm и AmneziaWG, фаервол
    config_patch.py         переделка ключей vpn:// и .conf
    keys.py                 ключи: выбирает модуль по тому, как стоит AmneziaWG
    keys_installer.py       ключи для amneziawg-installer (manage_amneziawg.sh)
    keys_docker.py          ключи для Amnezia в docker, админский ключ
    mobile.py               Android-версия (Toga)
    __main__.py             точка входа для Briefcase
pyproject.toml              конфигурация Briefcase (Android)
.github/workflows/build.yml сборка всех платформ в GitHub Actions
build.bat, build.sh         локальная сборка настольных версий
docs/                       документация и FAQ
```
