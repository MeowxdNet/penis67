# Penis 6.7 // Wibecode pro max nano
## It real

# Penis67 — плагин для meow-client

Имплемент **penis67** (P67) для меовклаента: собственный стелс-протокол
уровня REALITY с шейрлинками `penis67://…`. Один AntiNet-модуль
(MODULE_API v1); клиент и ядро менять не нужно.

| Схема | Носитель | TCP | UDP | Camouflage |
|---|---|---|---|---|
| `penis67://` | TLS 1.3 / TCP **или** QUIC / UDP (H3) | ✅ (mux) | ✅ (datagram-фреймы) | uTLS fp + sid-маркер + decoy-relay + per-conn серты |

## Идея протокола (insane edition, research-driven)

1. **Маркер внутри полей, случайных по определению.** Аутентификация
   клиента занимает `legacy_session_id` (32 байта — в каждом TLS 1.3 hello
   они случайны для совместимости с мидлбоксами), её эфемеральный ключ —
   **классическая x25519-полуструктура собственного key_share хендшейка**
   (чистый X25519 либо хвост гибрида X25519MLKEM768, который шлёт Chrome).
   AES-256-GCM с байт-точным паритетом REALITY: nonce =
   ClientRandom[20:32], **AAD = весь ClientHello с занулённым sid-слотом**
   (маркер нельзя пересадить в другой hello). **В ClientHello нет ни одного
   байта, которого не было бы у обычного браузера.**
2. **Decoy-relay вместо отказа.** Сервер до отправки первого байта парсит
   ClientHello: маркер не открылся — соединение **сплайсится в настоящее
   время на decoy-сайт**. Активный пробер ТСПУ получает подлинный
   сертификат Microsoft и подлинную страницу (проверено openssl вживую).
3. **Per-connection сертификаты с имперсонацией.** При старте сервер
   скачивает настоящий серт декаоя и на каждое авторизованное соединение
   выписывает свежий ECDSA-серт, зеркалящий Subject/SAN/keyUsage декаоя,
   со случайным серийником и «пожившей» валидностью — статического
   отпечатка серта (JA4X) не существует (фикс из REALITY-rkn-fix).
4. **uTLS-отпечатки + ротация.** `fp=chrome|firefox|safari|ios|android|
   edge|random|mixed` (mixed — новый отпечаток на каждое подключение).
   GREASE-ECH вырезается из отпечатка по умолчанию (ECH душится в РФ;
   `ech=1` возвращает). Отпечатки без x25519-шэра автоматически падают на
   второй носитель (`hide=ext`, расширение 0x2F47).
5. **Нет TLS-в-TLS + мукс = доказанный антидетект.** Классификатор
   вложенных TLS-хендшейков (USENIX Sec'24, Xue et al.) даёт >70% TPR на
   стандартных прокси, но **при мультиплексировании живого трафика детект
   падает до 1.17%** — P67 гоняет всё через один муксованный носитель.
6. **Поведенческая маскировка.** ТСПУ (модель «июня 2026») ловит по AND:
   много TLS-коннов к одному эндпоинту, симметричный up/down (туннель 1:2
   против веба 1:10+), ровные пакеты. Ответ: один носитель на всё
   (mc=1 по умолчанию), **асимметричный паддинг** (сервер тяжелее —
   downlink-профиль 100-4100B, клиент 16-624B), размер чанков
   1.2-16KB по веб-гистограмме, burst-breaker каждые 512KB, idle-шум
   PING 8-96B.
7. **Фрагментация ClientHello.** `frag=N&fragd=ms` — первый флайт
   сегментами ≤N байт (техника xray `fragment`; против ТСПУ 1..200).
8. **0-RTT open (опция, по умолчанию выкл).** `rtt0=1` — первый стрим в
   том же флайте, что и auth. По умолчанию off: как REALITY, сначала
   проверка сервера (HMAC-challenge с привязкой
   `HKDF(uuid, sha256(ephPub‖certDER‖alpn))`), ноль утечек.
9. **QUIC/H3 носитель.** `net=quic` — тот же мукс поверх QUIC-стрима,
   ALPN h3, **стандартный congestion control** (FOCI'25: кастомные CCA
   типа Brutal детектируются тривиально). Стелс-флагман (sid-маркер,
   decoy-relay) — TCP-only: QUIC Initial не несёт наш маркер без своего
   стека; авторизация — v2 auth-пакетом (uid + channel-bound HMAC),
   чужие закрываются.
10. **Флоу-контроль.** Формат кадров несёт WINDOW (credit-based, как
    yamux/h2), но пер-стрим гейтинг в v1 инертен: пейсинг полностью
    доверен нативному TCP/QUIC флоу-контролю — кастомный кредитный слой
    в стресс-тестах умел вешать сессии способами, которых у TCP нет.
    Формат готов к ужесточению без ломки совместимости.

Честно про остаточные риски: ServerHello авторизованных сессий —
Go-флейвор (как у xray REALITY; JA4S `t130200_1301_*`); «0 детектов» не
бывает — бывает «неотличимо от браузерного трафика к популярному
сайту». Практика против ТСПУ-2026: нестандартный порт вместо 443 спасает
в ~80% случаев (хабр-обзоры), decoy должен быть живым популярным сайтом.

## Ссылка

```
penis67://<uuid>@host:port?fp=chrome&hide=sid&sni=www.bing.com&pbk=<b64url-x25519>&dpy=www.bing.com&dport=443&net=tcp&frag=0&fragd=20&rtt0=0&mc=1&pad=1#имя
```

* `uuid` — ключ пользователя (36 или 32 hex);
* `fp` — отпечаток uTLS (`mixed` — ротация);
* `hide` — носитель маркера: `sid` (по умолчанию) или `ext`;
* `sni`/`pbk`/`dpy`/`dport` — SNI, статический ключ сервера (обязателен), decoy;
* `net` — `tcp` (по умолчанию) или `quic`;
* `frag`/`fragd` — фрагментация ClientHello (выкл / 20 мс);
* `rtt0` — 0-RTT open (по умолчанию выкл);
* `mc` — параллельные носители 1..4 (по умолчанию 1; >1 — триггер «много
  коннов к одному эндпоинту», только для жирного канала);
* `ech` — разрешить ECH в отпечатке (по умолчанию выкл); `pad` — паддинг (вкл).

## Сервер

```bash
go build -o penis67-server ./cmd/penis67-server
./penis67-server -gen -host vps.example.com:443 -uuid <uuid>   # ключи + линк
./penis67-server -listen :443 -uuid <uuid>[,<uuid2>] \
  -priv <b64url-из--gen> -decoy www.bing.com:443
```

Серверу не нужны домен и сертификат: своим — per-connection
self-signed (клиент проверяет через pbk, поля зеркалят decoy), чужим —
подлинный cert decoy-сайта через relay.

## Сборка плагина

```bash
cd plugins/penis67
go test ./...
python3 scripts/build_penis67.py arm64-v8a
# все ABI: python3 scripts/build_penis67.py arm64-v8a armeabi-v7a x86_64 x86 --desktop
```

Нужны Go ≥ 1.26 и NDK 28.x. Зависимости: `refraction-networking/utls`,
`quic-go`, общий `net.meowxd.modcommon` (replace на `../common`).

## Тесты

`go test ./internal/...` — линки, оба носителя маркера (AAD-паритет),
парсер key_share (вкл. MLKEM-гибрид), аудит чистоты hello (нет 0x2F47/ECH
в sid-режиме), фрагментация, флоу-контроль (768KB через мукс),
multi-carrier, per-conn серты, e2e-туннель TCP+UDP, decoy-relay (пробер
получает родной серт), QUIC e2e, отказ чужому UUID. Live:
`P67_LIVE=1 go test ./internal/p67 -run TestLive -v`.

## Research digest (источники решений)

* Xue et al., USENIX Security'24 — «Fingerprinting Obfuscated Proxy
  Traffic with Encapsulated TLS Handshakes»: mux как контрмера.
* XTLS REALITY internals — sid-маркер, MlkemEcdhe, HMAC-cert auth.
* fwflunky/REALITY-rkn-fix — per-connection серты против JA4X.
* Хабр-разборы ТСПУ 2025-2026 (слои детекции, поведенческий AND-триггер,
  порты, fragmentation) + net4people/bbs #546.
* FOCI'25 — «Is Custom Congestion Control a Bad Idea for Circumvention
  Tools?» (почему QUIC-носитель на стандартном CC).

## Я официально не принимаю это и точка
