# penis67 — модуль AntiNet (MODULE_API v1)

**Penis 6.7 // Wibecode pro max nano — It real.**

REALITY-класс стелс-протокол: для цензора соединение неотличимо от браузерного
HTTPS к популярному сайту, активные пробы получают подлинный сертификат и
страницу декаоя, своим — муксованный туннель (TCP + UDP) с поведенческой
маскировкой.

## Как это работает (коротко)

1. **Маркер в `legacy_session_id`.** Аутентификация — 32 байта AES-256-GCM в
   поле, случайного по определению в каждом TLS 1.3 hello. Ключ — HKDF от
   ECDH с статическим ключом сервера; эфемеральный ключ маркера — собственная
   x25519-полуструктура key_share (чистый X25519 или хвост X25519MLKEM768).
   Байт-точный паритет REALITY: nonce = ClientRandom[20:32], AAD = весь
   ClientHello с занулённым sid-слотом. В ClientHello нет ни одного байта,
   которого не было бы у Chrome.
2. **Decoy-relay.** Маркер не открылся → соединение сплайсится в настоящий
   decoy-сайт (по умолчанию `www.bing.com:443`): подлинный сертификат,
   подлинная страница. Своим — терминирование TLS и мукс.
3. **Per-connection серты.** При старте сервер скачивает реальный серт
   декаоя и каждым коннектам выписывает свежий ECDSA-серт с его Subject/SAN,
   случайным серийником и «пожившей» валидностью — JA4X-отпечатка нет.
4. **uTLS + ротация.** `fp=chrome|firefox|safari|ios|android|edge|random|
   mixed`. GREASE-ECH вырезан по умолчанию (ECH душится в РФ); отпечатки
   без x25519-шэра автоматически падают на `hide=ext`.
5. **Поведенческая маскировка.** Асимметричный паддинг (сервер тяжелее —
   downlink-профиль), чанки 1.2–16KB по веб-гистограмме, burst-breaker,
   idle-шум PING. Один носитель на всё: `mc=1` по умолчанию (много коннов к
   одному эндпоинту — самостоятельный сигнал ТСПУ).
6. **Носители.** `net=tcp` (стелс-флагман: sid-маркер + decoy-relay) или
   `net=quic` (H3-ALPN, стандартный congestion control — кастомные CCA
   детектируются, FOCI'25).

## Ссылка

```
penis67://<uuid>@host:port?fp=chrome&hide=sid&sni=www.bing.com&pbk=<b64url-x25519>&dpy=www.bing.com&dport=443&net=tcp&frag=0&fragd=20&rtt0=0&mc=1&pad=1#имя
```

| Параметр | Значение |
|---|---|
| `uuid` | ключ пользователя, 8-4-4-4-12 или 32 hex |
| `fp` | отпечаток uTLS; `mixed` — ротация на подключение |
| `hide` | `sid` (дефолт, ноль лишних байт) / `ext` (расширение 0x2F47) |
| `sni` | SNI в ClientHello (дефолт: host; для стелса — имя декаоя) |
| `pbk` | **обязательный** статический X25519 публичный ключ сервера (base64url) |
| `dpy`/`dport` | decoy для релея чужих (дефолт: sni, 443) |
| `net` | `tcp` (дефолт) / `quic` |
| `frag`/`fragd` | фрагментация ClientHello по TCP-сегментам (0 / 20 мс) |
| `rtt0` | 0-RTT открытие первого стрима (по умолчанию выкл — как REALITY, сначала verify-server) |
| `mc` | параллельные носители 1..4 (дефолт 1) |
| `pad` | паддинг-фреймы (вкл по умолчанию) |
| `ech` | разрешить ECH в отпечатке (выкл по умолчанию — ECH душится в РФ) |

## Сервер

`native/penis67/cmd/penis67-server`:

```bash
go build -o penis67-server ./cmd/penis67-server
./penis67-server -gen -host vps.example.com:443 -uuid <uuid>  # ключи + линк
./penis67-server -listen 0.0.0.0:443 -uuid <uuid> -priv <b64url> -decoy www.bing.com:443
```

Домен и сертификат серверу не нужны: своим — per-connection self-signed
(клиент аутентифицирует через `pbk`), чужим — подлинный сертификат декаоя.

## Сборка модуля

Из корня монорепо (SDK):

```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/28.2.13676358
python3 build.py --os android --module penis67 --abis arm64-v8a -y
# release-бандл: examples/modulepenis67/dist-release/penis67-android-arm64-v8a.zip
python3 build.py --os all --module penis67 --abis all --bundle -y   # всё сразу
python3 build.py --test --module penis67                            # go test с инжектом канонов
```

## Тесты

`cd examples/modulepenis67/native/penis67 && go test ./...` — маркеры (оба
носителя, AAD-паритет), парсер key_share (MLKEM-гибрид), аудит чистоты
hello, фрагментация, флоу-контроль (768KB), multi-carrier, per-conn серты,
e2e TCP+UDP, decoy-relay, QUIC e2e, отказ чужому UUID. Live против
запущенного сервера: `P67_LIVE=1 go test ./internal/p67 -run TestLive -v`.
