# AntiNet Module System — внутренности и кроссплатформенный порт

Этот документ — для тех, кто **портирует AntiNet-сторону** модульной системы на другую платформу
(Desktop) либо **чинит и расширяет** её. Контракт, который обязан соблюдать сам модуль, — в
`MODULE_API.md`; здесь — **как AntiNet этот контракт исполняет**: какой компонент за что отвечает,
точные входы-выходы на каждой границе и потоки коннекта, пинга, хендовера и teardown, которые порт
обязан воспроизвести.

> Источник истины — Kotlin-код в репозитории AntiNet (`app/src/main/java/com/antinet/vpn/`; в
> авторский архив модуля он не входит — там только сторона модуля). Все имена ниже —
> реальные классы и методы; при расхождении верь коду. Порт — это зеркало этих потоков один в один.

---

## 1. Компоненты AntiNet-стороны (кто за что отвечает)

| Компонент (файл) | Ответственность |
|---|---|
| **`module/ModuleManager.kt`** (object) | **Сердце.** Discovery модулей (скан `files/modules/<id>/module.json`) плюс весь lifecycle слот-процесса: `claim` слота из пула, `dlopen` скачанной `.so` через C-шим, ожидание маркера `ready`, кэш эндпоинта, watchdog смерти, рекавери на хендовере, teardown, heartbeat. Плюс `installedModules()` (дескрипторы для UI: имя, `version` из `module.json`, описание, схемы, `updateUrl`, `homepage`), `checkUpdate(updateUrl)` (GET JSON-манифеста → `ModuleUpdate`), `installBundle` (rollback-safe подмена каталога) и **единый разбор маркеров живого stdout** (`forEachNewProgressLine` / Pascal `TailProgress`: `PROGRESS\|`, `LOG\|`, `ACTION_REQUIRED\|`, `ACTION_CLOSE\|`, `STATE_SAVE\|`, `STATUS\|`, `EVENT_ACK\|`) — один парсер на оба читателя, стартовый poll и сессионный тейл. Платформо-специфичен: Android — слот-`Service` и `bindService`, Desktop форкает процесс. |
| **`module/ModuleSlot.kt`** | Обёртка над одним слот-процессом (`android:process=":modN"`, восемь обезличенных слотов в манифесте — Android не даёт регистрировать процессы динамически). Повторяет ровно ту часть поверхности `java.lang.Process`, которой пользуется `ModuleManager` (`isAlive`/`kill`/`waitForDeath`), поэтому вся супервизор-логика осталась структурно нетронутой при переезде с `ProcessBuilder` на слот. Один модуль на слот за всю жизнь процесса: два Go-рантайма в процессе дают конфликт `crosscall2` и SIGURG. |
| **`module/ModuleListener.kt`** | Слушающий SOCKS5-сокет поднимает хост и передаёт слоту через `ParcelFileDescriptor` по тому же Binder-каналу (Desktop — наследованием fd, номер в `ANTINET_LISTEN_FD`; Windows — только `LISTEN_PORT`, сокет биндит сам модуль). Порт известен сразу и авторитетно; переживает смерть и подмену модуля (входящие копятся в backlog вместо `ECONNREFUSED`); `socks.port` выродился в маркер `ready`. |
| **`module/ModuleActionActivity.kt`** | UI интерактивного действия (§2.8) рисует хост: `confirm`, `form`, `choice`, `display` (в том числе QR), `webview`. У модуля нет APK, и UI нести негде. |
| **`module/ModuleProtocolHandler.kt`** | Мост «модуль ↔ реестр протоколов», один экземпляр на схему. `parse` (ссылка → `VpnConfig`), `emit` (→ `socks`-outbound поднятого модуля, иначе `null` — аутбаунд не собран; анти-утечка живёт слоем выше, в `emitPrimaryNode`), `export`, `signatureParts`, `socksOutbound` (общий билдер socks-блока). Платформо-агностичен, кроме вызовов `ModuleManager`. |
| **`protocol/ProtocolRegistry`** | Реестр `ProtocolHandler`'ов. `registerDiscoveredModules(ctx)` (из `AntiNetApp.onCreate` + на смену пакетов) регистрирует `ModuleProtocolHandler` на каждую найденную схему, поэтому разбор, генерация, экспорт и дедупликация идут единым швом, как для встроенных протоколов. |
| **`models/Models.kt`** | `VpnConfig.ext["moduleLink"]` — непрозрачная ссылка. `isModuleBacked()` — признак module-конфига. `canBeCascade() = !isModuleBacked()`: модуль не может быть каскадом (вторым хопом), но может быть основой. |
| **`service/VpnHealthMonitor.kt`** | Здоровье уже поднятой module-сессии. `probeVpnLiveness`/`probeAndRecoverPinned` берут потолок пробы через `ModuleManager.tunnelProbeBudgetMs`: модуль объявляет свою цену, потому что общий потолок для built-in конфигов ему мал. На отказ — двухуровневая эскалация: щадящий `signalLiveModuleIfSupported` (тот же event, что на хендовере), и только на исчерпание backoff'а — реальный relaunch. Гейт `moduleReportsUnrecoverableByNudge(scheme)` пропускает лестницу нуджей сразу к relaunch'у, когда модуль сам объявил `STATUS\|waiting` или `fatal` (§2.13) — по типизированному состоянию, с фоллбэком на разбор хвоста stdout для модулей без `STATUS\|`. |
| **`service/VpnTunnelLifecycle.kt`** | На connect-пути для `isModuleBacked()`: `ModuleManager.reconcileActiveHelper(scheme, link, verbose=true)` **до** генерации конфига (`ep == null` → abort и DISCONNECTED). `applyAppRouting`: с модели v3 модуль — это слот-процесс того же пакета, что AntiNet, поэтому per-package TUN-исключение для модуля не годится (слот включён в TUN как часть своего пакета, инвариант Husi-pattern); egress модуля идёт мимо туннеля единственно через socket-level `protect()` (`SCM_RIGHTS`). Набор `modulePkgs` в `applyAppRouting` держится пустым намеренно, это не забытый мёртвый код. |
| **`tunnel/singbox/SingboxConfigGenerator.kt`** | `emitLeafMember` → `buildProxyOutbound` → `handler.emit`. Путь один и у коннекта, и у пинга: `generateGroupPingConfig` зовёт тот же `emitLeafMember`, поэтому форма socks-блока у волны и у туннеля совпадает по построению. `domain_resolver` и диалерные опции модульному аутбаунду не навешиваются — гейт `isModuleBacked` внутри генератора. |
| **`tunnel/singbox/SingboxTunnelModule.kt`** | `softReload` отказывается (`return false`) при смене конфига к module-конфигу, от него или между ними (`config.id` сменился и одна из сторон `isModuleBacked()`) → оркестратор откатывается на полный `buildAndStartTunnel` → reconcile, потому что своп не способен поднять helper нового конфига. Reload того же module-конфига (DNS, стратегия, каскад) свопом проходит нормально. |
| **`tunnel/TunnelManager.kt`** | `pingConfigsFastUrlTest` — обёртка над `pingBatchInternal`: разделение на built-in и `parallelPing`-модули (один параллельный под-батч) и sequential-модули (по одному — свой helper); под-батчи сериализованы; `stopForPing` по схеме в `finally`. |
| **`tunnel/singbox/DefaultNetworkMonitor.kt`** | На смене реального дефолт-интерфейса → `ModuleManager.onHandover()`: helper в отдельном процессе сигнала сети не получает, его надо рестартить. |
| **`service/AntiNetVpnService.kt`** | `finalizeDisconnectedState` → `ModuleManager.stopAll()` — session-end teardown обоих disconnect-путей. На `onDestroy` полагаться нельзя: его отменяет quick-reconnect. |
| **`tunnel/singbox/SingboxCoreHolder`** | `startModuleProtect(path)` / `stopModuleProtect()` (standalone protect-сервис) + `resetNetwork()` (расклин DNS после relaunch helper'а). |
| **libcore `module_protect.go`** (Go) | `StartModuleProtect(PlatformInterface, path)` / `StopModuleProtect()`: отдельно стоящий `protect.Service` (UNIX-сокет, `SCM_RIGHTS`-приёмник fd → `VpnService.protect` через `autoDetectInterfaceControl`). К sing-box box'у не привязан: модуль стартует раньше него. |
| **`viewmodel/VpnViewModel.kt`** | Гарды каскада: `setCascadeConfig`/`addCascadeMemberToPool` отвергают module-конфиг (`!canBeCascade()` → toast). **+ state экрана «Модули»**: `installedModules`/`moduleUpdateStates` StateFlow + `refreshInstalledModules`/`checkModuleUpdate`/`checkAllModuleUpdates`. |
| **`ui/settings/ModulesScreen.kt`** | UI-карточка «Модули» (Настройки → Модули): список установленных модулей (имя · `version` из `module.json` · описание · схемы · ссылка), авто-проверка обновлений (JSON-манифест `updateUrl`, сравнение `version` посегментно числами) и **тихая** установка бандла в `files/modules/<id>/` — ни установщика, ни промптов: модуль это файл, а не APK. Платформо-специфичен (Compose UI). |

---

## 2. Границы вход-выход (точный I/O-контракт)

```
┌─ DISCOVERY ──────────────────────────────────────────────────────────────────┐
│ in : скан каталога модулей (Android `files/modules/<id>/module.json`;         │
│      Desktop `<exe>/modules/<id>/module.json`) — обе платформы одинаково       │
│ out: scheme → ModuleInfo(dir, helperBinary, parallelPing, handoverMode,        │
│                          hostEvents)                                           │
│      (ModuleManager.discover)                                                  │
└────────────────────────────────────────────────────────────────────────────┘
┌─ PARSE (импорт ссылки) ───────────────────────────────────────────────────────┐
│ in : raw "scheme://…"                                                          │
│ out: VpnConfig(name, protocol=scheme, server, port=0, ext["moduleLink"]=raw)   │
│      имя/сервер ← `helper summarize <link>` (parse-only сабкоманда, без        │
│      подъёма data-plane); #fragment перебивает (ModuleProtocolHandler.parse)   │
└────────────────────────────────────────────────────────────────────────────┘
┌─ CONFIG (хост передаёт содержимым перед стартом; на диск не пишется) ─────────┐
│ in : link + per-session SOCKS5 (user/pass/port=0)                              │
│ out: content = LISTEN_PORT/SOCKS_USER/SOCKS_PASS + LINK=<сырая ссылка>         │
│      (Android — C-строка через слот; Desktop — base64 в ANTINET_MODULE_CONFIG); │
│      helper самодекодит LINK тем же парсером, что summarize/normalize          │
└────────────────────────────────────────────────────────────────────────────┘
┌─ HELPER (Android: dlopen в зарезервированный слот-процесс; Desktop: форк) ────┐
│ in : конфиг-содержимое (выше) + profileDir + protectPath — без configPath      │
│ out: SOCKS5-листенер 127.0.0.1:<port>, сокет которого создал и передал хост;   │
│      порт известен хосту сразу; маркер `ready` (не файл socks.port с числом)   │
│ side: каждый исходящий fd → SCM_RIGHTS на protectPath (off-TUN bypass-mark)     │
│       PR_SET_PDEATHSIG=SIGKILL (Desktop; Android — lifecycle ведёт хост);      │
│       stdout → helper.stdout.log, никогда не недренируемый pipe (Android — хост │
│       отдаёт слоту путь, слот делает dup2 до dlopen, ModuleHostService.ERR_STDIO;│
│       Desktop — poUsePipes + TDrainThread, дренирует в тот же файл). Маркеры,    │
│       которые хост построчно ловит из этого файла:                              │
│       PROGRESS|/LOG|/ACTION_REQUIRED|/ACTION_CLOSE|/STATE_SAVE|/STATUS|/EVENT_ACK| │
│ in (обратный канал): Android — C-ABI antinet_module_event (приём доказывает rc);│
│       Desktop — построчный stdin (ACTION_RESULT|<id>|<payload>, handover), приём │
│       доказывает ответный EVENT_ACK| — трубе верить нельзя (§2.8)               │
└────────────────────────────────────────────────────────────────────────────┘
┌─ EMIT (генерация sing-box конфига) ───────────────────────────────────────────┐
│ in : VpnConfig + ModuleManager.cachedEndpoint(scheme, link)                    │
│ out: {"type":"socks","server":"127.0.0.1","server_port":port,                  │
│       "version":"5","username":user,"password":pass}                          │
│      модуль не поднят → null: аутбаунд не собран, как у любого другого.         │
│      Анти-утечка живёт слоем выше — emitPrimaryNode ставит {"type":"block"}     │
│      под тегом основы, то есть там, где утечка вообще возможна. Здесь тот же    │
│      block попадал и на путь пинга: волна мерила его и писала о сервере         │
│      «тоннель глушит трафик», не отправив ему ни пакета.                        │
│      (ModuleProtocolHandler.emit / .socksOutbound)                            │
└────────────────────────────────────────────────────────────────────────────┘
┌─ PROTECT (off-TUN) ───────────────────────────────────────────────────────────┐
│ helper fd ──SCM_RIGHTS──► protectPath ──► protect.Service ──► VpnService.protect│
│ Один путь, без спецветок: fd приезжает через SCM_RIGHTS+adoptFd, то есть он наш.│
│ ⛔ Пина fd к физсети на data-path нет: SELECT_NETWORK присваивает               │
│ protectedFromVpn = canProtect(...), то есть вне окна владения VPN он стирает    │
│ bypass-метку → сокет уходит в наш же TUN (правило 12000 раньше 13000).          │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Потоки (что порт обязан воспроизвести)

### 3.1. Коннект
1. Оркестратор выбрал module-конфиг (`isModuleBacked()`).
2. `VpnTunnelLifecycle.buildAndStartTunnel` (на IO, **до** генерации конфига) → `ModuleManager.reconcileActiveHelper(scheme, link, verbose=true)`:
   - глушит все live-helper'ы кроме нужной схемы (switch-away cleanup),
   - `ensureStarted(scheme, link, verbose=true)`: хост открывает и владеет SOCKS5-сокетом (`ModuleListener`) →
     собирает конфиг-содержимое (KEY=VALUE + сырая `LINK=`) → `SingboxCoreHolder.startModuleProtect(<noBackupFiles>/module_protect_path)` →
     Android — `dlopen`'ит скачанную `.so` в зарезервированный слот-процесс и передаёт слушающий сокет
     по Binder-каналу; Desktop — форкает `<helperBinary>`, передавая сокет наследованием fd
     (Windows — только номер зарезервированного порта, модуль биндит сам) → helper самодекодит `LINK`
     из переданного содержимого → poll маркера `ready` (≤95с) → `Endpoint(port,user,pass)`.
   - `ep == null` → abort и DISCONNECTED: продолжать с битым конфигом нельзя.
3. Генерация конфига: `handler.emit` → `socks`-outbound на `127.0.0.1:port` с per-session кредами. Модуль off-TUN — единственно через socket-level protect (набор `modulePkgs` в `applyAppRouting` для модулей держится пустым намеренно: слот в том же пакете, что и хост, per-package исключение не годится — см. §4, инвариант 9).
4. sing-box поднят → трафик: app→TUN→sing-box→socks(127.0.0.1)→helper→протокол→exit.

### 3.2. Пинг
`TunnelManager.pingConfigsFastUrlTest`:
- **Разделение**: `mainConfigs` (built-in и `parallelPing`-модули) против `moduleSeq` (sequential-модули, `protocol ∈ ModuleManager.sequentialPingSchemes()`).
- `moduleSeq` пуст → ранний `return pingBatchInternal(configs)`: обычный built-in путь, без модульной обвязки.
- Иначе: `runSub(mainConfigs)` — один параллельный под-батч, затем по одному `runSub([moduleCfg])` на каждый sequential (его pre-pass `ensureStarted(verbose=false)` поднимает или переиспользует helper). Под-батчи сериализованы `pingMutex` (singleton `urlTestResultCallback` не коллизит); прогресс пересчитывается в общий `grandTotal`.
- **Безопасность для коннекта**: пинг того же link, что у активного коннекта, переиспользует живой helper; пинг соседней ссылки той же схемы при активном коннекте пропускается — запуск соседа убил бы коннект. Исключение — схемы, объявившие `parallelPing` или `pingWhileConnected`: у них сессия пинга отдельная и коннекту не мешает. `finally` волны зовёт `pingHelperRelease(<ключ сессии>)` по каждому взятому заимствованию, и ключ берётся у `pingSessionKey(схема, ссылка)` — той же формулой, что и при взятии.
- **Почему sequential**: сессия ключуется парой «схема + роль» (`live[<схема>]`, `live[<схема>#ping]`), поэтому у схемы без `parallelPing` живёт ровно один link на роль. Несколько одно-схемных в общий параллельный батч нельзя: живой socks достаётся последнему, остальные получают `-2`. `parallelPing: true` декларирует, что схема выдержит несколько live-helper'ов — и хост это исполняет: ключ становится `<схема>#ping#<отпечаток ссылки>`, сессий столько же, сколько ссылок, конфиги остаются в параллельном батче. Потолок — свободные слоты пула минус один, зарезервированный под коннект; упёрлись — `busyBorrowed`, и конфиг уходит в повтор волны, а не получает `-2`.

### 3.3. Хендовер (смена сети)
`DefaultNetworkMonitor` (смена реального интерфейса) → `ModuleManager.onHandover()`:
- Дебаунс `HANDOVER_DEBOUNCE_MS` = 2 с, коалесинг (флап WiFi ↔ мобильная сеть даёт один рестарт) и сериализация: однопоточный `handoverExec`, поэтому гонки за фиксированный порт нет.
- `recoverAllHelpers` → `restartOne` на каждый живой: kill (`destroyForcibly` + `waitFor`) и `relaunchHelper` на тот же стабильный порт.
- После relaunch — `SingboxCoreHolder.resetNetwork()`, а не `reloadInstance`: порт стабилен, retarget не нужен. `resetNetwork` — это `connectionManager.CloseAll()` плюс `Client.DrainInflight()`, расклинивает DNS-петлю за микросекунды.
- Режим по умолчанию (`handoverMode: "restart"`): мягкий in-place self-heal отвергнут как общее правило, потому что in-place reset обычно не достаёт резолверы на новой сети. Остаётся cold-restart со свежим процессом — протокол-агностично.
- Опциональный `handoverMode: "signal"`: helper не убивается, ему шлётся событие, дальше он чинит себя сам. **Уважают обе платформы**: Android — C-ABI `antinet_module_event(<причина>)` (не SIGUSR1: POSIX-сигналы в слот-процессе под ART недетерминированы), Desktop — построчный stdin (`SendHostEventToLive`, тот же канал, что у `ACTION_RESULT|…`; сигналы там не участвуют вовсе). Неуспех — процесс мёртв или событие не принято — откатывает на cold-restart. Структура зеркальна: Android `recoverAllHelpers` → `restartOne` → `notifyModule`; Desktop `RecoverAllHelpers` → `RestartOne` → `TrySignalHandover` → `NotifyModule` → `SendHostEventAcked` (щадящая ветка — та же функция, что зовёт health-монитор, одна реализация на оба вызывающих).
- **Причина события — часть контракта** (`hostEvents`, `MODULE_API.md` §2.8). Их четыре: `handover` (сеть сменилась), `netlost` (годной сети нет), `netback` (появилась снова), `stall` (сеть та же, но проба хоста через модуль не прошла). Дескриптор перечисляет те, которые модуль разбирает; `handover` парсер добавляет всегда. Подмена необъявленной причины — одна дверь на платформу (`wireCause` / `WireCause`): `stall` → `handover` (health-нудж и раньше приходил этой строкой), `netlost` и `netback` не шлются вовсе (их у хоста раньше не было, а `handover` вместо них — ложь про смену сети), `stop` и `ACTION_RESULT|…` — не причины и идут как есть. Инвариант: старый модуль на новом хосте получает ровно то же, что получал раньше, а новый модуль на старом хосте — только `handover`, поэтому причины обязаны быть оптимизацией, а не условием работы.
- Источник `netlost` и `netback` — тот же владелец дефолтной сети, что и у хендовера (Android `DefaultNetworkMonitor.setDefaultNetwork`, Desktop `TNetworkPoller.CheckModuleHandover`), и адресуются они в том числе стартующим сессиям: именно в окне подъёма модуль жжёт свой стартовый бюджет.
- **«Принято» ≠ «записано».** Android читает код возврата C-ABI-вызова (`-2` — обработчика нет). У Desktop канал однонаправленный, поэтому модуль обязан ответить `EVENT_ACK|<event>` в stdout, а `NotifyModuleEvent` ждёт его до 2,5 с — это полтора цикла сессионного тейла, который и разбирает маркер; второго читателя `helper.stdout.log` не заводится. Без ack модуль, объявивший `"signal"` и не читающий stdin, отменял бы себе cold-restart и оставался с протухшими сокетами. См. `MODULE_API.md` §2.8.

### 3.4. Teardown
- **Disconnect** → `AntiNetVpnService.finalizeDisconnectedState` → `ModuleManager.stopAll()`: инкремент `stopGeneration`, kill всех helper'ов, `stopModuleProtect`. Именно `finalizeDisconnectedState` — session-end обоих disconnect-путей, — а не `onDestroy`: quick-reconnect его отменяет, и остаются helper-зомби.
- **Конец пинга** → возврат заимствований по ключам сессий; `stopForPing(scheme)` остаётся входом «снести все пинговые сессии схемы» (у `parallelPing` их несколько) — для сброса состояния, удаления модуля, обновления.
- **Защита от зомби**: `ensureStarted` ловит `stopGeneration`, сменившийся за время блокирующего cold-test (около 36 с), и тогда не добавляет helper в `live`, а зовёт `destroyForcibly` — узкая гонка между connect-cold-test и disconnect.

### 3.5. Смена сервера (switch to/from/between module)
- `SingboxTunnelModule.softReload`: `config.id` сменился и при этом `config.isModuleBacked()` либо `connected.isModuleBacked()` → `return false` → оркестратор → `buildAndStartTunnel` → `reconcileActiveHelper(newScheme, newLink)`:
  - модуль → другой модуль другой схемы, либо модуль → не-модуль: глушит старый helper, иначе остаётся зомби;
  - та же схема, другая ссылка: `ensureStarted` сам вытесняет старый;
  - не-модуль: `scheme = null` — глушит все helper'ы.
- Reload того же module-конфига (DNS, стратегия, переключение каскада) проходит свопом: helper жив, кэш валиден.

### 3.6. Watchdog смерти helper'а
`startWatcher` (поток на `process.waitFor()`) → на смерть `superviseDeath` (на `handoverExec`, сериализован):
- Остановлен или заменён — не воскрешать; иначе `relaunchHelper` на тот же порт (три ретрая), новый watcher и `resetNetwork`.
- Защита от крэш-петли: `crashLoopMaxDeaths` (по умолчанию 5) быстрых смертей подряд — быстрых, то есть с аптаймом короче `crashLoopWindowSec` (по умолчанию 15 с), — дают **backoff и ре-арм** (`scheduleRearm`, лестница 30 → 60 → 120 → 300 с, эскалация по раунду, с потолком), а не отказ навсегда: причина крэш-петли обычно временная (сеть, сервер), и при её уходе helper поднимается сам, без ручного реконнекта. Оба порога модуль может объявить сам (§2.10 `MODULE_API.md`).

---

## 4. Инварианты — не ломать при порте и правках

1. **Слушающий SOCKS5-сокет создаёт и передаёт хост**, а не модуль (Android — Binder и `ParcelFileDescriptor`; Desktop Unix — наследование fd; Desktop Windows — хост резервирует номер порта, модуль сам биндит именно его). Порт известен хосту сразу и переживает смерть или подмену модуля.
2. **helper: `PR_SET_PDEATHSIG=SIGKILL`** (Desktop — форкнутый процесс; на Android lifecycle ведёт хост-слот, отдельный `PDEATHSIG` не требуется) — умереть вместе с родителем, чтобы не осталось сироты.
3. **Стабильный порт на relaunch**: outbound не нужно ретаргетить, достаточно `resetNetwork` вместо дорогого `reloadInstance`.
4. **Декод ссылки — в Go-helper'е**: сабкоманды `summarize` и `normalize` плюс самодекод `LINK` на коннекте. Никакого Kotlin-`SubprocessEntry`. Сабкоманды — чистый парсинг, без Go-рантайма data-plane.
5. **helper stdout идёт в файл** (`Redirect.to`), а не в недренируемый pipe: иначе data-plane виснет на переполнении pipe-буфера.
6. **`emit` при не поднятом модуле даёт `block`** (анти-утечка), а не `direct` и не `null`: direct-фоллбэк означает трафик мимо VPN и реальный IP.
7. **Module-конфиг не бывает каскадом** (`canBeCascade() = false`): socks локален (`127.0.0.1`) и как удалённый второй хоп недостижим. Основой быть может.
8. **Смена module-конфига идёт через `buildAndStartTunnel` и reconcile**, а не свопом: своп не поднимет helper нового конфига, получатся битый `block` и зомби.
9. **Модуль off-TUN — только через socket-level protect (`SCM_RIGHTS`)**, не через package-level TUN-исключение. С модели v3 модуль — это слот-процесс и скачанный файл в том же пакете, что хост, поэтому механизм вроде `addDisallowedApplication` для модуля не работает в принципе (весь пакет включён в TUN): если protect не сработал, egress модуля петлял бы через собственный туннель.
10. **Teardown сессионных ресурсов — в `finalizeDisconnectedState`**, не в `onDestroy`: quick-reconnect отменяет `onDestroy`.

---

## 5. Кроссплатформенный порт (что переиспользуется, что переписать)

**Контракт и helper платформо-агностичны** — переиспользуются как есть:
- Сам **helper-бинарь** (Go): парсинг конфига (`KEY=VALUE` плюс `LINK=`), SOCKS5 и protect-fd-IPC. Платформо-специфичен только механизм доставки содержимого: Desktop — переменная окружения `ANTINET_MODULE_CONFIG` (argv-путь оставлен легаси-фоллбэком), Android — C-строка параметром C-ABI-вызова, argv не участвует вовсе. Один Go-исходник, разные build-таргеты.
- **Сабкоманды декода** (`summarize`, `normalize`, самодекод `LINK` на коннекте): чистый парсинг внутри Go-бинаря, переносится как есть — на Desktop тот же бинарь, JVM-glue не нужен.
- **SOCKS5-chaining**: sing-box-сторона цепляет `socks`-outbound на `127.0.0.1:port` — идентично на любой платформе.

**Платформо-специфична только обёртка** (`ModuleManager` и protect) — её на Desktop переписывают:

| Что | Android | Desktop-порт (уже реализовано) |
|---|---|---|
| **Discovery** | скан каталога `files/modules/<id>/module.json` | скан каталога `<exe>/modules/<id>/module.json` (те же ключи schemes/helperBinary/parallelPing/handoverMode/hostEvents + сгенерированный `bundleTarget`; `build.py` генерит этот dist-`module.json` из дескриптора) |
| **Запуск helper'а** | `dlopen` скачанной `.so` (`c-shared`) в зарезервированный слот-процесс (`:mod0`..`:mod7`) через C-шим | `exec` бинаря из каталога установки модуля (форк; нативка грузится свободно — W^X не мешает) |
| **Off-TUN (protect)** | `SCM_RIGHTS` UNIX-сокет → `VpnService.protect` — единственный механизм: с модели v3 package-level TUN-исключение для модуля не годится, слот в том же пакете и UID, что хост | канон `shared/offtun`: `SO_BINDTODEVICE`, `IP_UNICAST_IF`, `IP_BOUND_IF` — bind сокета helper'а к физическому интерфейсу, независимо от routing, hijack и состояния туннеля |
| **Handover-сигнал** | `DefaultNetworkMonitor` → C-ABI `antinet_module_event` (не SIGUSR1 — доставка сигнала в слот-процессе под ART недетерминирована) | Desktop-мониторинг смены дефолт-сети → `OnHandover()`; `handoverMode="signal"` → построчный stdin-event (`SendHostEventToLive`), иначе и на неуспех → kill (relaunch делает watcher) |
| **Пропажа/возврат сети** | `DefaultNetworkMonitor.setDefaultNetwork` (единственный писатель дефолтной сети) → `ModuleManager.onNetworkAvailability` → причина `netlost`/`netback` живым И стартующим (`launchingSlots`) | `TNetworkPoller.CheckModuleHandover` (там же, где читается fingerprint адаптера) → `ModuleManager.OnNetworkAvailability` → `TModuleNetEventThread` → те же причины живым и стартующим (`GLaunchProcs`) |
| **stopAll на disconnect** | `finalizeDisconnectedState` | session-end хук Desktop-демона |

**Чеклист Desktop-порта `ModuleManager`-эквивалента** (1:1 потоки §3):
1. discover: скан каталога модулей → `(scheme→helperBinary/entry/parallelPing)`.
2. ensureStarted: собрать конфиг-содержимое (`KEY=VALUE` плюс сырая `LINK=`, без записи на диск) и резолверы → создать и передать SOCKS5-сокет (хост владеет им, порт известен сразу) → старт protect-IPC → запустить helper с содержимым (helper самодекодит `LINK`) → poll маркера `ready` → endpoint.
3. emit: `socks`-outbound на `127.0.0.1:port` (или `block`).
4. watchdog смерти + relaunch на тот же порт + resetNetwork.
5. onHandover: kill+cold-relaunch (дебаунс+коалесинг+сериализация).
6. teardown: stopAll на disconnect, stopForPing на конце пинга.
7. exclude egress helper'а из TUN.
8. Все инварианты §4: стабильный порт, `block`-фоллбэк, запрет каскада, смена конфига через rebuild.
9. Опционально, UI: карточка «Модули» — список установленных (имя, версия, описание, ссылка), авто-проверка обновлений по JSON-манифесту (сравнение `version` посегментно числами) и тихая установка бандла в каталог модуля. Версия — `version` из `module.json`, она единственная: парного `versionCode` в контракте нет.

> Пишите модуль и helper так, чтобы они не знали платформу — тогда модуль заработает и на
> Desktop-порте без изменений, поменяется только обёртка на стороне клиента.
