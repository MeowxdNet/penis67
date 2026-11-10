// SPDX-License-Identifier: MIT
//
// echo helper — МИНИМАЛЬНЫЙ subprocess-helper протокол-модуля AntiNet (см. MODULE_API.md §2.3).
//
// Это эталонный template: простейший data-plane, который просто пробрасывает трафик НАПРЯМУЮ
// (passthrough, без своего протокола) — чтобы показать ОБЯЗАТЕЛЬНУЮ обвязку, общую для ЛЮБОГО
// модуля. Замени тело dial'а (`net.Dialer.Dial` в handleConn) на свой wire-протокол — остальное
// (SOCKS5-фронт, socks.port, protect-fd, PDEATHSIG) остаётся как есть.
//
// Аргументы (форкает AntiNet):  helper <configPath> <resolversPath> <profileDir> <protectPath>
//
//	configPath    — KEY=VALUE-конфиг от хоста (LISTEN_PORT/SOCKS_USER/SOCKS_PASS/LINK=<сырая ссылка>);
//	                единый формат обеих платформ — и Android ModuleManager, и Desktop пишут его одинаково
//	resolversPath — файл резолверов (echo не использует — passthrough)
//	profileDir    — writable-каталог (сюда пишем socks.port)
//	protectPath   — UNIX-сокет protect-сервиса AntiNet (SCM_RIGHTS bypass-mark на off-TUN сокеты)
//
// Helper ОБЯЗАН: слушать SOCKS5 → записать реальный порт в <profileDir>/socks.port → протектить
// КАЖДЫЙ исходящий сокет через protectPath → умереть с родителем (PR_SET_PDEATHSIG).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Платформенного кода в этом файле НЕТ НИ СТРОЧКИ, и это норма контракта, а не особенность echo:
// точки входа даёт канон shared/entry, разговор с хостом — shared/hostproto, примитивы жизненного
// цикла (PDEATHSIG, oom_score_adj, десктопный stdin-читатель событий) — shared/lifecycle, а
// protect-хук `dialControl` приезжает под ОДНИМ именем с обеих сторон: shared/protect на Android
// (SCM_RIGHTS) и shared/offtun на десктопе (bind к физ-адаптеру). Поэтому один и тот же helper-код
// собирается под Android (GOOS=android) и под windows/linux/darwin без единого build-тега.
// См. MODULE_API.md §4 «Кроссплатформенность».

// normalizeEcho — мирор SubprocessEntry.normalizeImport: echo:label (bare) / JSON {"echo":…,"name":…}
// → канон echo://. Уже echo:// / пусто / не наш формат → "".
func normalizeEcho(raw string) string {
	t := strings.TrimSpace(raw)
	if t == "" || strings.HasPrefix(strings.ToLower(t), "echo://") {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(t), "echo:") {
		label := strings.TrimSpace(t[len("echo:"):])
		if label != "" {
			return "echo://" + label
		}
		return ""
	}
	if strings.HasPrefix(t, "{") {
		var m map[string]interface{}
		if json.Unmarshal([]byte(t), &m) != nil {
			return ""
		}
		label, _ := m["echo"].(string)
		label = strings.TrimSpace(label)
		if label == "" {
			return ""
		}
		name, _ := m["name"].(string)
		name = strings.TrimSpace(name)
		if name != "" {
			return "echo://" + label + "#" + name
		}
		return "echo://" + label
	}
	return ""
}

// moduleCall — parse-only сабкоманды контракта (MODULE_API §2.4). ОДНА реализация на обе формы
// доставки: desktop зовёт её из main() по argv, Android-слот — через C-ABI `antinet_module_call`
// (запускать .so ради парсинга ссылки нельзя — это библиотека, не процесс).
// Возврат — то же, что печаталось в stdout: имя и сервер через перевод строки (summarize),
// канон-ссылка (normalize), "" если verb неизвестен.
func moduleCall(verb, arg string) string {
	switch verb {
	case "summarize":
		name, server := "", ""
		if l, ok := parseEchoLink(arg); ok {
			name = l.name
			if name == "" {
				name = l.label
			}
			if name == "" {
				name = "echo"
			}
			server = l.label
			if server == "" {
				server = "passthrough"
			}
		}
		return name + "\n" + server
	case "normalize":
		return normalizeEcho(arg)
	case "canping":
		// §2.10 — «могу ли я сейчас пинговаться БЕЗ интерактива?». Хост зовёт это ТОЛЬКО у модулей,
		// объявивших `"pingNeedsConsent": true`, и ТОЛЬКО перед ФОНОВЫМ пингом (ручной одиночный
		// пинг конкретного конфига интерактив разрешает — там юзер смотрит на экран).
		//
		// Аргумент — три строки: <link>, <profileDir>, <§4-блоб состояния>. Хост даёт оба
		// хранилища и ничего не интерпретирует (§4.1 п.4) — модуль сам знает, где его состояние.
		// echo хранит consent-маркер в profileDir, поэтому блоб здесь не нужен.
		//
		// Ответ: `ok` — можно пинговать, `no` — нельзя (хост пропустит конфиг, оставив RTT в -1;
		// это НЕ «-2/мёртв» — на коннекте, где подтверждение спросить есть у кого, конфиг остаётся
		// полноценным кандидатом).
		//
		// ЭТАЛОННЫЙ СМЫСЛ для авторов модулей: отвечать «ok» надо тогда и только тогда, когда
		// подъём data-plane ГАРАНТИРОВАННО не потребует участия человека. Здесь это флаг действия
		// в ссылке и возраст consent'а: без флага диалога нет вовсе; с флагом внутри 15-минутного
		// окна (§4.2) реконнект идёт без диалога, значит и пинг пройдёт молча; за окном — echo
		// спросил бы подтверждение, а на фоновой волне отвечать некому, и модуль честно отказывается
		// вместо 95-секундного зависания и ложного «н/д».
		lines := strings.SplitN(arg, "\n", 3)
		link := strings.TrimSpace(lines[0])
		profileDir := ""
		if len(lines) > 1 {
			profileDir = strings.TrimSpace(lines[1])
		}
		// Ссылка без флага `?action=1` диалога не покажет никогда (@see echoLinkWantsAction) —
		// подъём data-plane человека не ждёт, фоновый пинг возможен всегда.
		if !echoLinkWantsAction(link) {
			return "ok"
		}
		// showDialog=false (юзер выключил демо-диалог в карточке «Модули») → echo вообще ничего не
		// спрашивает, значит и фоновый пинг всегда возможен. Настройка приезжает конфигом, которого
		// у parse-вызова нет, поэтому ориентируемся на само наличие consent'а: он записывается
		// только тогда, когда диалог реально показывался.
		if profileDir == "" {
			return "ok" // хост не дал profileDir (старый хост) → не мешаем пингу
		}
		// START_REASON у parse-вызова нет; "resume" — консервативно верное значение: consentValid
		// отвергает "cold", а холодность здесь неизвестна и не относится к вопросу «есть ли свежее
		// подтверждение». Возраст и отпечаток ссылки проверяются как обычно.
		if _, ok := consentValid(profileDir, "resume", link); ok {
			return "ok"
		}
		return "no"
	}
	return ""
}

// realMain — ОБЩЕЕ тело модуля для обеих форм доставки (desktop-процесс и Android-слот).
// configContent — СОДЕРЖИМОЕ конфига, не путь (§3: секреты мимо диска). listenFd — готовый
// слушающий сокет от хоста (§2.6); <=0 значит «биндить самому по LISTEN_PORT».
// Возврат — код выхода (0 = нормальное завершение; на практике функция не возвращается, пока жив
// SOCKS5-цикл).
func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	_ = resolversPath // echo не использует (passthrough)
	// Канал событий хоста (§3): ACTION_RESULT|<id>|<payload> + handover. Desktop — stdin,
	// Android-слот — прямой C-ABI-вызов (там это no-op).
	// ⚠ САМЫМ ПЕРВЫМ: интерактивное действие эмитится ещё ДО маркера готовности, и если читатель
	// stdin поднять после него, ответ хоста некому будет забрать — модуль провисит до таймаута.
	// Ловится живьём: канал доставил, а читатель ещё не поднялся.
	startHostEventReader()
	dieWithParent()
	// (3b) защититься от OOM/vendor-killer'ов САМОМУ. Android: снижает /proc/self/oom_score_adj
	//     до -1000 — ActivityManager этот forked-child вообще не видит и не защищает независимо
	//     от родителя. Десктоп: no-op.
	protectFromOomKill()

	cfg := parseConfig(configContent)
	port, _ := strconv.Atoi(cfg["LISTEN_PORT"]) // 0 = эфемерный (ядро выберет)
	user := cfg["SOCKS_USER"]
	pass := cfg["SOCKS_PASS"]
	// §4.1 п.3 — причина старта от хоста: cold | resume | handover. Хост НЕ интерпретирует наше
	// состояние (§4.1 п.4), он лишь называет повод; годность consent'а решаем мы сами.
	startReason := strings.TrimSpace(cfg["START_REASON"])
	if startReason == "" {
		startReason = "cold" // старый хост без START_REASON — консервативно считаем холодным
	}
	link := cfg["LINK"]
	// ⏱ Таймаут дозвона — см. обоснование у net.Dialer в handleConn. Считаем ОДИН раз здесь, а не
	// на каждое соединение: настройка за время жизни сессии не меняется.
	dialTimeout := 5 * time.Second
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_dialTimeoutSec"])); err == nil && v > 0 {
		dialTimeout = time.Duration(v) * time.Second
	}
	// DNS_SERVERS=<ip[,ip...]> — реальные физические DNS-сервера, которыми хост населяет ЛЮБОЙ
	// модуль (тот же choke point, что LISTEN_PORT/SOCKS_USER/SOCKS_PASS/LINK). Пусто (старый хост) →
	// resolver сам фоллбэкнет на обычный net.DefaultResolver — см. dns.go для полного обоснования.
	resolver := newProtectedResolver(cfg["DNS_SERVERS"], protectPath)

	// APP_LANG=<ru|en> (MODULE_API §2.9) — эффективный язык AntiNet, хост его резолвит из своего
	// собственного language-setting (НЕ сырая OS-локаль модуля — юзер мог явно выставить AntiNet
	// на другой язык, чем система). Демо ниже показывает РЕАЛЬНОЕ использование: локализуемый текст
	// действий (form/choice/display/дефолт confirm) выбирается по этому ключу, а не хардкожен.
	lang := strings.TrimSpace(cfg["APP_LANG"])
	s := demoStringsFor(lang)
	// ── Настройки модуля (MODULE_API §2.11): хост пишет SETTING_<key>=<value> из карточки «Модули»
	//    (юзер-оверрайд ?: дефолт декларации module.json). Helper читает их как обычные cfg-ключи. Здесь
	//    демонстрация всех трёх типов: bool (showDialog) / string (dialogText) / int (autoCloseSec).
	showDialog := cfg["SETTING_showDialog"] != "false" // дефолт true (декларация default=true)
	dialogText := cfg["SETTING_dialogText"]
	if strings.TrimSpace(dialogText) == "" {
		dialogText = s.confirmDefault
	}
	autoCloseSec, _ := strconv.Atoi(cfg["SETTING_autoCloseSec"]) // 0 = без автозакрытия
	// §2.8 ось 2 — действие ПОСРЕДИ живой сессии, а не только на коннекте. До Фазы 2 это было
	// невозможно структурно: хост читал stdout helper'а лишь до маркера готовности, и всё, что
	// модуль эмитил позже, уходило в никуда. Настройка задаёт задержку от `ready` до эмита (0=выкл).
	midSessionSec, _ := strconv.Atoi(strings.TrimSpace(cfg["SETTING_midSessionSec"]))
	// §2.8 — какие из пяти типов действий прогнать демо-последовательностью (CSV). Дефолт
	// "confirm" — дефолт (он же намеренная crash-канарейка), остальные типы включаются юзером
	// в карточке «Модули».
	demoTypes := strings.Split(cfg["SETTING_demoTypes"], ",")
	if strings.TrimSpace(cfg["SETTING_demoTypes"]) == "" {
		demoTypes = []string{"confirm"}
	}
	// §2.7 — параметры декларативного правила для типа `webview`, объявленные в module.json пятью
	// ключами. ⚠ Объявить ключ в дескрипторе мало: если его никто не ЧИТАЕТ, карточка «Модули»
	// показывает юзеру ручку, которая ничего не делает. Здесь они читаются, а прежние
	// захардкоженные значения служат дефолтами.
	rich := richRuleSettings{
		mode:     strings.TrimSpace(cfg["SETTING_richActionMode"]),
		url:      strings.TrimSpace(cfg["SETTING_richActionUrl"]),
		pattern:  strings.TrimSpace(cfg["SETTING_richActionPattern"]),
		jsonPath: strings.TrimSpace(cfg["SETTING_richActionJsonPath"]),
		param:    strings.TrimSpace(cfg["SETTING_richActionParam"]),
	}

	// (0) ОБРАБОТЧИК СОБЫТИЙ ХОСТА — ПЕРВЫМ ДЕЛОМ, до листенера и до долгого подъёма.
	//
	// ⛔ ЭТАЛОННЫЙ ПОРЯДОК, а не стилистика. Пока обработчик не поставлен, канон подтверждает
	// событие (`EVENT_ACK` уходит на ЛЮБОЕ) и молча его выбрасывает: хост считает доставленным,
	// модуль не узнаёт ничего. У echo подъём мгновенный, поэтому окно крошечное, — но у модуля
	// с дорогим стартом (OpenFlux ждёт транспорт до 90 с) в это окно попадает ровно тот
	// `netlost`, ради которого причина и заведена. Проверено запуском: при регистрации ПОСЛЕ
	// подъёма в stdout идут четыре `EVENT_ACK` и ни одной строки реакции.
	setHostEventHandler(func(event string) {
		switch event {
		case "handover":
			// Сеть СМЕНИЛАСЬ: сокеты привязаны к ушедшей — РЕАЛЬНЫЙ модуль пересоздаёт их здесь.
			emitProgress("%s", s.progressNetworkChanged)
			emitLog(s.logHandover)
		case "netlost":
			// Сети нет вовсе. Дозваниваться некуда: РЕАЛЬНЫЙ модуль здесь поднимает флаг и
			// перестаёт жечь попытки — иначе досидит свой таймаут подъёма и умрёт «транспорт не
			// поднялся» ровно тогда, когда чинить нечего.
			emitLog(s.logNetLost)
		case "netback":
			// Сеть вернулась — пробовать НЕМЕДЛЕННО, не досиживая собственный backoff.
			emitLog(s.logNetBack)
		case "stall":
			// Сеть та же, но хост не смог проверить связь ЧЕРЕЗ модуль: передозвониться, ничего
			// не заявляя про смену сети (иначе юзер прочитает «сменилась сеть», когда не менялась).
			emitLog(s.logStall)
		}
		// ⚠ Ветки для `dns=` здесь НЕТ намеренно. Это единственная причина с полезной нагрузкой,
		// и её забирает КАНОН: новый список от хоста сам доезжает до резолвера и сбрасывает его
		// кэш (см. `newProtectedResolver`). Модулю остаётся объявить `"dns"` в `hostEvents`
		// дескриптора — иначе хост событие не пришлёт, — и не писать ни строки обработчика.
	})

	// (1) SOCKS5-листенер. Стабильный LISTEN_PORT из config — чтобы relaunch на хендовере поднял
	//     тот же порт (AntiNet не меняет outbound). 0 → эфемерный, реальный порт уйдёт в socks.port.
	ln, err := openListener(port, listenFd)
	if err != nil {
		log.Fatalf("listen 127.0.0.1:%d: %v", port, err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port

	// PROGRESS|<текст> в stdout → тост прогресса в AntiNet (ТОЛЬКО connect-путь; на пинге игнор).
	// Демонстрация прогресс-канала (MODULE_API.md §2.3): свой helper шлёт milestone'ы по ходу старта.
	emitProgress(s.progressSocksUpFmt, actualPort)

	// ЭТАЛОННЫЙ ШАБЛОН (MODULE_API.md §2.13): как только data-plane реально готов —
	// объявить состояние. У echo путь тривиален (слушатель поднялся = работаем), у
	// настоящего модуля здесь стоит момент «релей установлен / апстрим ответил».
	// Держать состояние АКТУАЛЬНЫМ — часть контракта: упёрся во внешний лимит → шли
	// statusWaiting, вернулся в норму → снова statusOK, иначе прежнее залипнет у хоста.
	emitStatus(statusOK, "")

	// ── DEMO интерактив-действия по ходу коннекта (MODULE_API.md §2.7) — ГАТИМ флагом в ссылке
	//    (echo://<label>?action=1, @see echoLinkWantsAction) И настройкой showDialog (карточка «Модули»):
	//    без флага echo — чистый passthrough (pingable, без действия), юзер выключил диалог — тоже.
	//    ИДИОМА: эмить ACTION_REQUIRED ТОЛЬКО когда действие реально нужно (у тебя — напр. авто-капча
	//    не решилась). Эмить ДО socks.port (AntiNet ловит сигнал, пока ждёт готовности; на время действия
	//    его connect-таймаут на паузе; на пинге — fast-fail). Хост пишет сырую ссылку в LINK= (обе
	//    платформы пишут одинаково), helper сам её декодит. РЕАЛЬНЫЙ модуль гейтит «нужно ли действие»
	//    собственной логикой (qWDTT — авто-капча не решилась). dialogText/autoCloseSec — тоже из настроек.
	// §4.2 контракта (MODULE_API.md) — ОБРАЗЦОВЫЙ time-boxed consent, третий (наряду с qWDTT «полное
	// восстановление» и MasterDNS «намеренно cold») паттерн контракта восстановления.
	// Подтверждение юзера хранится НЕ БОЛЕЕ 15 минут в profileDir (durable — переживает смерть
	// слота, force-stop клиента, ручную остановку туннеля): любой реконнект внутри окна идёт БЕЗ
	// диалога, за окном / при START_REASON=cold / при смене ссылки — спрашиваем снова.
	//
	// ⚠ Взаимодействие с инвариантом «повторный confirm у echo — намеренная crash-канарейка:
	// backoff/подавление ЗАПРЕЩЕНЫ». Окно эту канарейку внутри 15 минут глушит,
	// поэтому на каждом переиспользовании consent'а echo пишет ОТДЕЛЬНЫЙ маркер RESUME| — падение
	// остаётся наблюдаемым в логе, просто сигналом другого вида, а не молча проглатывается.
	if showDialog && echoLinkWantsAction(link) {
		if age, ok := consentValid(profileDir, startReason, link); ok {
			fmt.Printf("%s RESUME|consent reused, age=%.0fs (window %.0fs, START_REASON=%s)\n",
				time.Now().Format("15:04:05.000000"), age.Seconds(), consentTTL.Seconds(), startReason)
			_ = os.Stdout.Sync()
		} else {
			demoInteractiveAction(profileDir, dialogText, autoCloseSec, demoTypes, rich, s)
			storeConsent(profileDir, link)
		}
	}

	if err := writeReady(profileDir, actualPort); err != nil {
		// ⛔ ОБРАЗЕЦ ДЛЯ АВТОРОВ МОДУЛЕЙ: причина неподъёма обязана уйти хосту ЯВНО, через
		// `LOG|` (`emitLog`), а не только в stderr.
		//
		// `log.Fatalf` сам по себе достаточен, чтобы отказ не был немым: процесс умирает, хост
		// видит `alive=false` и печатает хвост stdout. Но хост при этом показывает СЫРОЙ хвост,
		// а `LOG|` — это строка, которая попадает в ВИДИМЫЙ лог AntiNet как есть (оба хоста
		// разбирают её вне гейтов: Desktop `modulemanager.pas:2553`, Android
		// `ModuleManager.kt:2125` → AppLogger). Разница ровно в том, прочитает ли юзер причину
		// или увидит «модуль не запустился».
		//
		// Почему это в скелете, а не только в боевых модулях: копируют ИМЕННО отсюда. Класс
		// ошибки типовой — модуль не поднялся и молчит (немой вис в ожидании транспорта,
		// истёкший дедлайн, проваленный в `select {}`), и каждый такой случай стоит полной
		// сессии расследования ровно потому, что наружу не уходит НИЧЕГО.
		emitLog(s.logStartFailedFmt, err)
		// И ТИПИЗИРОВАННО (§2.13) — тот же дуплет, что у masterdns: `LOG|` читает юзер,
		// `STATUS|` читает хост. `fatal`, а не `degraded`: маркер готовности не записан,
		// пересоздавать щадящим сигналом нечего.
		emitStatus(statusFatal, "write ready marker failed")
		log.Fatalf("write ready marker: %v", err)
	}
	log.Printf("echo helper: SOCKS5 on 127.0.0.1:%d  protect=%s", actualPort, protectPath)

	// ── ДЕЙСТВИЕ ПОСРЕДИ ЖИВОЙ СЕССИИ (§2.8 ось 2) ────────────────────────────────────────────────
	// Реальный кейс: токен протух через час, сервер требует step-up-подтверждения, капча всплыла на
	// ре-авторизации. Всё это происходит ПОСЛЕ готовности, когда туннель уже несёт трафик.
	//
	// ⚠ Отмена мид-сессионного действия НЕ рвёт сессию — в отличие от connect-пути, где отказ от
	// обязательного действия означает «коннект не состоится» (abortConnect). Здесь туннель уже жив, и
	// решение «что значит отказ» принадлежит модулю: echo просто логирует. Реальный модуль,
	// которому подтверждение действительно необходимо для продолжения, выйдет сам — хост увидит
	// смерть процесса и отработает своим watchdog'ом, как при любой другой смерти.
	if midSessionSec > 0 {
		go func() {
			time.Sleep(time.Duration(midSessionSec) * time.Second)
			id := fmt.Sprintf("demo-midsession-%d", time.Now().UnixNano())
			res, cancelled := runAction(profileDir, id, map[string]any{
				"type": "confirm",
				"text": fmt.Sprintf(s.midSessionText, midSessionSec),
			})
			if cancelled {
				log.Printf("echo demo mid-session: CANCELLED (session keeps running, not a connect-path abort)")
				emitLog(s.logMidSessionCancelled)
				return
			}
			log.Printf("echo demo mid-session: %s", res)
			emitLog(s.logMidSessionConfirmedFmt, res)
		}()
	}

	// (4) ХЕНДОВЕР (MODULE_API.md §2.8). Дескриптор объявляет `handoverMode: "signal"` → AntiNet на
	//     смене дефолтной сети шлёт helper'у СОБЫТИЕ `handover` (helper НЕ убивается, в отличие от
	//     дефолтного "restart" = kill+cold-restart). ОБРАБОТЧИК ОБЯЗАН переустановить ДОЛГОЖИВУЩИЕ
	//     сеть-сокеты/сессии модуля на ТЕКУЩЕЙ сети (создать НОВЫЕ сокеты — protect-callback хоста
	//     привяжет их к новому дефолту), переиспользуя дорогой cold-state (креды/сессия/MTU) → БЕЗ
	//     полного cold-restart. echo — passthrough БЕЗ долгоживущей сессии (каждый SOCKS-конн дайлит
	//     свежо в handleConn → новые конны авто-привязываются к новой сети), поэтому здесь демо-no-op.
	//     РЕАЛЬНЫЙ модуль здесь: закрыть протухшие сокеты/relay + переустановить на новой сети (пример —
	//     qWDTT: cancel+re-spawn TURN/DTLS-воркеров на кэшированных кредах). ⚠ Если in-process
	//     переустановить НЕЛЬЗЯ (сервер держит сессию на старом source-IP) — НЕ объявляй "signal"
	//     (оставь дефолт "restart" → хост сделает kill+cold-restart). События редки (AntiNet дебаунсит).
	//     ТРАНСПОРТА ДВА, оба приводят СЮДА ЖЕ (через `handleHostEvent`): Android — C-ABI-экспорт
	//     `antinet_module_event("handover")` (канон shared/entry), десктоп — построчный stdin
	//     (`startHostEventReader`). Сигналов не шлёт ни один хост — обработчик SIGUSR1 был бы
	//     мёртвым кодом.
	// Обработчик событий хоста стоит ВЫШЕ — см. блок (0): регистрация после подъёма теряет
	// события, пришедшие в окно старта.

	// Accept-петля — канон shared/socks5: транзиентная ошибка её не роняет, закрытый листенер
	// завершает. Своя копия обычно умеет только одну половину — и тогда либо крутится вечно на
	// закрытом листенере, либо гибнет от первого же EMFILE.
	serveSocksListener(ln, func(c net.Conn) {
		handleConn(c, user, pass, protectPath, dialTimeout, resolver)
	})
	return 0
}

// Протокол разговора с хостом целиком — канон `shared/hostproto`: `emitProgress`/`emitLog`/
// `emitStatus`(+`status*`-константы)/`emitEventAck`/`emitActionClose`, `handleHostEvent` +
// `setHostEventHandler`, `runAction`/`awaitActionResult`, `parseConfig`/`readConfigForEntry`,
// `openListener`. Здесь копий больше нет: маркеры, формат конфига и владение слушающим сокетом —
// это сам контракт, а не утилиты модуля.
//
// `writeReady` — канон `shared/lifecycle`; точки входа (C-ABI-экспорты и argv-разбор) — канон
// `shared/entry`; protect-адаптер `dialControl` — каноны `shared/protect` (android) и
// `shared/offtun` (десктоп).

// ── §4.2 — time-boxed consent (образец для авторов модулей) ─────────────────────────────────────
//
// Третий паттерн контракта восстановления, наряду с «полное восстановление» (qWDTT кэширует
// TURN-креды) и «намеренно всегда cold» (MasterDNS: reuse без переПробинга давал 88 подряд
// DNS-фейлов, см. MODULE_API). Здесь — середина: подтверждение живёт ОГРАНИЧЕННОЕ время.
//
// Хранится в profileDir, который хост гарантирует durable (§4.1 п.1): переживает смерть слота,
// force-stop клиента, перезапуск/обновление AntiNet, хендовер и ручную остановку туннеля; стирается
// только при удалении модуля или явном «сбросить состояние модуля».
//
// В файле — ВРЕМЯ и ХЭШ ССЫЛКИ, но НЕ сама ссылка: в ней апстримный секрет (§3 «секреты не
// касаются диска»). Хэш нужен ровно чтобы заметить смену ссылки — сравнивать, не раскрывая.
const consentTTL = 15 * time.Minute

func consentPath(profileDir string) string { return filepath.Join(profileDir, "consent.state") }

// echoLink — разобранная ссылка `echo://<label>[?action=1][#name]`.
type echoLink struct {
	label, name string
	wantsAction bool // флаг демо-действия на коннекте
}

// parseEchoLink — ОДИН разбор ссылки на всех потребителей: summarize (имя и сервер карточки),
// realMain и canping (флаг действия). Разойдись разборы, сервер карточки нёс бы хвост query
// (`label?action=1`), а фоновая волна пропускала бы пингуемое либо ждала диалога. Флаг читается
// из query, а не подстрокой: «action=10» и «xaction=1» — не он. Без флага echo — чистый
// passthrough: подключается и пингуется без человека.
func parseEchoLink(link string) (echoLink, bool) {
	rest := strings.TrimSpace(link)
	if !strings.HasPrefix(strings.ToLower(rest), "echo://") {
		return echoLink{}, false
	}
	rest = rest[len("echo://"):]
	var l echoLink
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		l.name = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		q, err := url.ParseQuery(rest[i+1:])
		l.wantsAction = err == nil && q.Get("action") == "1"
		rest = rest[:i]
	}
	l.label = strings.TrimSpace(rest)
	return l, true
}

// echoLinkWantsAction — ссылка просит демо-действие на коннекте (@see parseEchoLink).
func echoLinkWantsAction(link string) bool {
	l, ok := parseEchoLink(link)
	return ok && l.wantsAction
}

// linkFingerprint — необратимый отпечаток ссылки. FNV-1a достаточно: задача не
// криптографическая (мы не защищаемся от подбора, а лишь замечаем «ссылка стала другой»),
// а вот класть в файл саму ссылку с `pass=` внутри — прямое нарушение §3.
func linkFingerprint(link string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.TrimSpace(link)))
	return strconv.FormatUint(h.Sum64(), 16)
}

// consentValid — можно ли пропустить диалог. Возвращает возраст подтверждения (для RESUME-маркера).
// Отказ на: cold-старте (юзер сбросил состояние либо его не было), смене ссылки, истёкшем окне,
// битом/отсутствующем файле. Любая неоднозначность трактуется как «спросить снова» — консервативно.
func consentValid(profileDir, startReason, link string) (time.Duration, bool) {
	if startReason == "cold" {
		return 0, false
	}
	raw, err := os.ReadFile(consentPath(profileDir))
	if err != nil {
		return 0, false
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), " ")
	if len(parts) != 2 {
		return 0, false
	}
	unixSec, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || parts[1] != linkFingerprint(link) {
		return 0, false
	}
	age := time.Since(time.Unix(unixSec, 0))
	if age < 0 || age > consentTTL {
		return 0, false
	}
	return age, true
}

// storeConsent — зафиксировать факт подтверждения. Атомарно (tmp→rename): иначе смерть слота
// посреди записи оставила бы обрезанный файл, который consentValid всё равно отвергнет, но лишний
// раз спросит юзера.
func storeConsent(profileDir, link string) {
	body := strconv.FormatInt(time.Now().Unix(), 10) + " " + linkFingerprint(link)
	tmp := consentPath(profileDir) + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, consentPath(profileDir))
}

// abortConnect — ИДИОМА реального модуля на отказ от обязательного действия (капча/логин):
// выйти, НЕ записав маркер готовности → AntiNet увидит смерть процесса → коннект не состоится.
func abortConnect(reason string) {
	log.Printf("echo demo action: %s -> exiting (connect will not complete)", reason)
	os.Exit(1)
}

// demoStrings — РЕАЛЬНАЯ реализация «модули отвечают за локализацию сами» (MODULE_API §2.9). Ключ —
// APP_LANG из конфига (хост резолвит его из СВОЕГО эффективного языка, а не из сырой OS-локали
// модуля). Незнакомое/пустое значение → английский (safe default для third-party пользователя без
// выбранного языка).
//
// Стол покрывает ОБА пользовательских приёмника, и это намеренно:
//   - текст, который демо-действия кладут в base64-payload `ACTION_REQUIRED` (§2.7);
//   - текст ПОСЛЕ тега в `PROGRESS|`/`LOG|` — юзер видит его тостом и на экране «Логи», значит он
//     обязан быть на языке AntiNet. Английский тост русскоязычному юзеру — это дыра в локализации,
//     пойманная живым репортом, а не стилистика.
//
// ⚠ Локализуется ТОЛЬКО payload. Сами теги (`PROGRESS|`/`LOG|`/`STATUS|`), таймстамп-префикс,
// `<detail>` у `STATUS|` и весь `log.Printf` — ASCII/английский всегда: теги разбирает хост, а
// `log.Printf` читает разработчик грепом.
type demoStrings struct {
	confirmDefault   string
	midSessionText   string // %d — секунд после ready
	formTitle        string
	// `text` — пояснение над содержимым, общее для всех типов действия (§2.7). Эталон обязан его
	// показывать: автор стороннего модуля, не найдя подсказки ни в контракте, ни здесь, написал
	// собственную форму поверх `injectJs` вместо одного правила.
	formText         string
	loginLabel       string
	otpLabel         string
	secretLabel      string
	rememberLabel    string
	choiceTitle      string
	choiceText       string
	regionEU         string
	regionUS         string
	regionAsia       string
	displayTitle     string
	displayText      string
	confirmCancelled string
	formCancelled    string
	choiceCancelled  string
	displayCancelled string

	// Демо `browser` (страница проверки): полоса окна и страницы, которые отдаёт сам echo.
	browserTitle       string
	browserText        string
	browserCheckTitle  string
	browserCheckText   string
	browserCheckButton string
	browserDoneText    string
	browserCancelled   string

	// payload PROGRESS|/LOG| (см. шапку типа)
	progressSocksUpFmt        string // %d — порт
	progressNetworkChanged    string
	logStartFailedFmt         string // %v — ошибка
	logHandover               string
	logNetLost                string
	logNetBack                string
	logStall                  string
	logMidSessionCancelled    string
	logMidSessionConfirmedFmt string // %s — ответ действия
}

var demoStringsRU = demoStrings{
	confirmDefault:   "Подтвердите подключение echo",
	midSessionText:   "Мид-сессионное действие echo: прошло %d с после готовности, туннель уже работает.",
	formTitle:        "Демо: ввод данных",
	formText:         "Это пояснение рисует хост из поля `text` — модулю для него не нужен ни HTML, ни webview.",
	loginLabel:       "Логин",
	otpLabel:         "Код из приложения",
	secretLabel:      "Пароль",
	rememberLabel:    "Запомнить",
	choiceTitle:      "Демо: выбор региона",
	choiceText:       "Пояснение к выбору — то же поле `text`, что и у формы.",
	regionEU:         "Европа",
	regionUS:         "США",
	regionAsia:       "Азия",
	displayTitle:     "Демо: код подтверждения",
	displayText:      "Введите код ABCD-1234 на сайте — окно закроется само.",
	confirmCancelled: "confirm cancelled by user",
	formCancelled:    "form cancelled by user",
	choiceCancelled:  "choice cancelled by user",
	displayCancelled: "display cancelled by user",

	browserTitle:       "Демо: страница проверки",
	browserText:        "Пройдите «проверку» на странице модуля — окно закроется само, как только вы с неё уйдёте.",
	browserCheckTitle:  "Страница проверки (её отдаёт echo)",
	browserCheckText:   "Эта страница поставила cookie пропуска. Нажмите ссылку — окно действия закроется и вернёт cookie модулю.",
	browserCheckButton: "Пройти проверку",
	browserDoneText:    "Проверка пройдена.",
	browserCancelled:   "browser demo cancelled by user",

	progressSocksUpFmt:        "echo: SOCKS5 поднят на 127.0.0.1:%d",
	progressNetworkChanged:    "echo: сеть сменилась — новые соединения пойдут через новый маршрут",
	logStartFailedFmt:         "не удалось записать маркер готовности: %v — выходим, чтобы хост перезапустил",
	logHandover:               "хендовер: сменилась сеть по умолчанию",
	logNetLost:                "сети нет — жду возвращения, попытки приостановлены",
	logNetBack:                "сеть вернулась — поднимаюсь немедленно",
	logStall:                  "хост не дождался ответа через меня — передозваниваюсь (сеть не менялась)",
	logMidSessionCancelled:    "мид-сессионное действие отменено (туннель продолжает работать)",
	logMidSessionConfirmedFmt: "мид-сессионное действие подтверждено: %s",
}

var demoStringsEN = demoStrings{
	confirmDefault:   "Confirm the echo connection",
	midSessionText:   "echo mid-session action: %d s elapsed since ready, tunnel is already up.",
	formTitle:        "Demo: data entry",
	formText:         "This note is drawn by the host from the `text` field — no HTML and no webview needed.",
	loginLabel:       "Login",
	otpLabel:         "App code",
	secretLabel:      "Password",
	rememberLabel:    "Remember me",
	choiceTitle:      "Demo: pick a region",
	choiceText:       "A note above the choice — the same `text` field the form uses.",
	regionEU:         "Europe",
	regionUS:         "US",
	regionAsia:       "Asia",
	displayTitle:     "Demo: confirmation code",
	displayText:      "Enter code ABCD-1234 on the website — the window closes itself.",
	confirmCancelled: "confirm cancelled by user",
	formCancelled:    "form cancelled by user",
	choiceCancelled:  "choice cancelled by user",
	displayCancelled: "display cancelled by user",

	browserTitle:       "Demo: checkpoint page",
	browserText:        "Pass the \"check\" on the module's page — the window closes itself as soon as you leave it.",
	browserCheckTitle:  "Checkpoint page (served by echo)",
	browserCheckText:   "This page has set a pass cookie. Follow the link — the action window closes and hands the cookie to the module.",
	browserCheckButton: "Pass the check",
	browserDoneText:    "Check passed.",
	browserCancelled:   "browser demo cancelled by user",

	progressSocksUpFmt:        "echo: SOCKS5 up on 127.0.0.1:%d",
	progressNetworkChanged:    "echo: network changed - new connections will use the new default",
	logStartFailedFmt:         "failed to mark readiness: %v - exiting so the host can restart",
	logHandover:               "handover: default network changed",
	logNetLost:                "no network - waiting for it to come back, attempts paused",
	logNetBack:                "network is back - coming up immediately",
	logStall:                  "the host saw no answer through me - re-dialing (network unchanged)",
	logMidSessionCancelled:    "mid-session action cancelled (tunnel keeps running)",
	logMidSessionConfirmedFmt: "mid-session action confirmed: %s",
}

// demoStringsFor — APP_LANG "ru" → русский стол, всё остальное (в т.ч. пусто/неизвестно) → английский.
// Правило выбора — канонное (`stringsForLang`, shared/hostproto): трактовка `APP_LANG`
// принадлежит хосту, а модулю — только СОДЕРЖИМОЕ таблиц.
func demoStringsFor(lang string) demoStrings {
	return stringsForLang(lang, demoStringsRU, demoStringsEN)
}

// demoInteractiveAction — ДЕМО ВСЕХ ПЯТИ типов §2.8 на референс-модуле плюс escape-hatch
// (`selfpage` — шестым значением CSV, но НЕ шестой тип контракта: это тот же `webview`, чей url
// указывает на страницу самого модуля). Какие именно прогонять — настройка `demoTypes` (CSV, дефолт
// "confirm" — он же намеренная crash-канарейка).
//
// `rich` — параметры декларативного правила для типа `webview` (§2.7), пришедшие из настроек
// модуля. Передаются параметром, а не глобалом: у демо нет причин быть stateful.
// `s` — локализованный стол строк (demoStringsFor выше), резолвленный ОДИН раз в realMain из
// APP_LANG и переданный сюда — тоже не глобал.
type richRuleSettings struct {
	mode     string // "" | "network" | "navigation"
	url      string
	pattern  string // endpointPattern для network / urlPattern для navigation
	jsonPath string // только network
	param    string // только navigation
}

func demoInteractiveAction(profileDir, text string, autoCloseSec int, types []string, rich richRuleSettings, s demoStrings) {
	for _, t := range types {
		switch strings.TrimSpace(strings.ToLower(t)) {
		case "confirm":
			res, cancelled := runAction(profileDir, "demo-confirm", map[string]any{
				"type": "confirm",
				"text": text,
			})
			if cancelled {
				abortConnect(s.confirmCancelled)
			}
			log.Printf("echo demo confirm: %s", res)

		case "form":
			res, cancelled := runAction(profileDir, "demo-form", map[string]any{
				"type":  "form",
				"title": s.formTitle,
				"text":  s.formText,
				"fields": []map[string]any{
					{"key": "login", "label": s.loginLabel, "type": "text", "default": "user"},
					{"key": "otp", "label": s.otpLabel, "type": "number"},
					{"key": "secret", "label": s.secretLabel, "type": "password"},
					{"key": "remember", "label": s.rememberLabel, "type": "bool", "default": true},
				},
			})
			if cancelled {
				abortConnect(s.formCancelled)
			}
			log.Printf("echo demo form: %s", res)

		case "choice":
			res, cancelled := runAction(profileDir, "demo-choice", map[string]any{
				"type":  "choice",
				"title": s.choiceTitle,
				"text":  s.choiceText,
				"options": []map[string]any{
					{"id": "eu", "label": s.regionEU},
					{"id": "us", "label": s.regionUS},
					{"id": "asia", "label": s.regionAsia},
				},
			})
			if cancelled {
				abortConnect(s.choiceCancelled)
			}
			log.Printf("echo demo choice: %s", res)

		case "display":
			// display + ACTION_CLOSE (§2.8 ось 3) — ровно то, ради чего этот тип существует отдельно
			// от confirm: показать код/QR и ЗАКРЫТЬ ОКНО САМОМУ, когда модуль досчитал, не дожидаясь
			// клика. Реальный кейс: device-code / push-подтверждение.
			const displayID = "demo-display"
			done := make(chan struct{})
			go func() {
				sec := autoCloseSec
				if sec <= 0 {
					sec = 5
				}
				select {
				case <-time.After(time.Duration(sec) * time.Second):
					emitActionClose(displayID)
				case <-done:
				}
			}()
			res, cancelled := runAction(profileDir, displayID, map[string]any{
				"type":  "display",
				"title": s.displayTitle,
				"text":  s.displayText,
				"qr":    "https://example.org/device?code=ABCD-1234",
				"link":  "https://example.org/device",
			})
			close(done)
			if cancelled {
				abortConnect(s.displayCancelled)
			}
			log.Printf("echo demo display: %s", res)

		case "webview":
			// Пятый тип — единственный, где UI-движок нужен настоящий (перехват сетевых ответов /
			// навигации). AntiNet исполняет декларативное ПРАВИЛО, ничего не зная о протоколе модуля.
			// Правило собирается из настроек модуля; пусто → захардкоженный демо-набор, чтобы
			// поведение «из коробки» работало без настройки. `network` и `navigation` различаются
			// ТОЛЬКО именами полей извлечения — сам движок один и тот же, и он в AntiNet.
			rule := map[string]any{"type": "webview", "urlTimeoutSec": 30}
			switch rich.mode {
			case "network":
				rule["mode"] = "network"
				rule["url"] = rich.url
				rule["endpointPattern"] = rich.pattern
				rule["jsonPath"] = rich.jsonPath
			case "navigation":
				rule["mode"] = "navigation"
				rule["url"] = rich.url
				rule["urlPattern"] = rich.pattern
				rule["param"] = rich.param
			default:
				rule["mode"] = "navigation"
				rule["url"] = "https://example.org/login"
				rule["urlPattern"] = "blank.html"
				rule["param"] = "access_token"
			}
			res, cancelled := runAction(profileDir, "demo-webview", rule)
			if cancelled {
				abortConnect("webview cancelled by user")
			}
			log.Printf("echo demo webview: %s", res)

		case "selfpage":
			// ESCAPE-HATCH (§2.8, «Что НЕ делается» п. про потолок выразительности): пять типов
			// покрывают перечислимые формы, а всё остальное модуль рисует САМ — поднимает свой
			// локальный HTTP-листенер, отдаёт СВОЮ страницу и забирает результат ТЕМ ЖЕ
			// декларативным правилом. AntiNet при этом не знает о модуле ничего нового: для него
			// это обычный `webview` с обычным urlPattern — просто адрес указывает на 127.0.0.1.
			//
			// Почему 127.0.0.1 работает на обеих платформах: WebView живёт в процессе AntiNet, модуль —
			// в соседнем процессе ТОГО ЖЕ устройства (Desktop — субпроцесс, Android — слот), общий loopback.
			srv, pageURL, want, serr := startSelfPage()
			if serr != nil {
				log.Printf("echo demo selfpage: failed to start own page: %v", serr)
				break
			}
			res, cancelled := runAction(profileDir, "demo-selfpage", map[string]any{
				"type":          "webview",
				"mode":          "navigation",
				"url":           pageURL,
				"urlPattern":    selfPageDonePath,
				"param":         "token",
				"urlTimeoutSec": 120,
			})
			_ = srv.Close()
			if cancelled {
				abortConnect("selfpage cancelled by user")
			}
			// Сверка с тем, что модуль сам положил на страницу — доказательство, что через хост
			// проехал РЕАЛЬНЫЙ результат со страницы модуля, а не какая-то заглушка.
			if strings.Contains(res, want) {
				log.Printf("echo demo selfpage: OK, token from own page arrived intact: %s", res)
			} else {
				log.Printf("echo demo selfpage: result does not contain expected token (wanted %q): %s", want, res)
			}

		case "browser":
			demoBrowserFlow(profileDir, s)
		}
	}
}

// ── Демо «страница проверки» — весь контракт окна `webview` (§2.7) на странице самого модуля ──────
//
// Сценарий капчи/входа, которого ждут реальные модули (SmartCaptcha, вход в аккаунт): страница
// проверки ставит HttpOnly-cookie пропуска и уводит на обычную страницу; модулю нужен именно этот
// cookie. Каждое поле правила — только если хост его объявил (`hostSupports`), иначе оно было бы
// молча проигнорировано: окно без `leavePattern` не завершится само, ответ придёт без cookie.
//
// Страницу отдаёт сам echo. Если хост умеет `proxy`, окно идёт через тот же листенер как через
// HTTP-прокси модуля на вымышленный хост `echo.demo` — ровно так модуль ведёт окно своим маршрутом
// (капча с адреса выходного узла).
func demoBrowserFlow(profileDir string, s demoStrings) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("echo demo browser: listen: %v", err)
		return
	}
	token := fmt.Sprintf("pass-%d", time.Now().UnixNano())
	const demoUA = "AntiNet-Echo-Demo/1"
	var seenUA, seenHeader, seenPreCookie string
	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.UserAgent()
		seenHeader = r.Header.Get("X-Echo-Demo")
		if c, _ := r.Cookie("echo_pre"); c != nil {
			seenPreCookie = c.Value
		}
		http.SetCookie(w, &http.Cookie{Name: "echo_pass", Value: token, Path: "/", HttpOnly: true})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><body style="font:16px sans-serif;padding:24px">
<h3>%s</h3><p>%s</p><p><a href="/ok" style="font-size:20px">%s</a></p></body>`,
			s.browserCheckTitle, s.browserCheckText, s.browserCheckButton)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><body style="font:16px sans-serif;padding:24px">%s</body>`,
			s.browserDoneText)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	base := "http://" + ln.Addr().String()
	rule := map[string]any{
		"type":          "webview",
		"title":         s.browserTitle,
		"text":          s.browserText,
		"urlTimeoutSec": 20,
	}
	if hostSupports("webview.proxy") {
		base = "http://echo.demo"
		rule["proxy"] = "http://" + ln.Addr().String()
	}
	rule["url"] = base + "/check"
	if hostSupports("webview.leavePattern") {
		rule["leavePattern"] = []string{"/check"}
	}
	if hostSupports("webview.doneButton") {
		rule["doneButton"] = true
	}
	if hostSupports("webview.userAgent") {
		rule["userAgent"] = demoUA
	}
	if hostSupports("webview.headers") {
		rule["headers"] = map[string]string{"X-Echo-Demo": token}
	}
	if hostSupports("webview.cookies") {
		rule["setCookies"] = []map[string]string{{"url": base + "/", "cookie": "echo_pre=" + token + "; Path=/"}}
		rule["collectCookies"] = true
	}
	if hostSupports("webview.session") {
		rule["session"] = "ephemeral"
	}
	res, cancelled := runAction(profileDir, "demo-browser", rule)
	if cancelled {
		abortConnect(s.browserCancelled)
	}
	env := actionResultEnvelope(res)
	check := func(feature string, ok bool) {
		switch {
		case !hostSupports(feature):
			log.Printf("echo demo browser: %s — host does not support it, skipped", feature)
		case ok:
			log.Printf("echo demo browser: %s OK", feature)
		default:
			log.Printf("echo demo browser: %s FAILED", feature)
		}
	}
	check("webview.userAgent", seenUA == demoUA)
	check("webview.headers", seenHeader == token)
	check("webview.cookies", seenPreCookie == token && actionResultCookieJar(res)["echo_pass"] == token)
	check("webview.leavePattern", strings.HasSuffix(fmt.Sprint(env["url"]), "/ok"))
	check("webview.proxy", strings.HasPrefix(fmt.Sprint(env["url"]), "http://echo.demo/"))
	log.Printf("echo demo browser: ended at %v", env["url"])
}

// ── Escape-hatch: своя страница со своего листенера ───────────────────────────────────────────────
// selfPageDonePath — путь «готово». Правило ловит НАВИГАЦИЮ на него и вынимает ?token=…; страница до
// этого может быть любой сложности (форма, JS, редиректы) — контракту это безразлично.
const selfPageDonePath = "/antinet-done"

// startSelfPage поднимает эфемерный listener на loopback и отдаёт страницу с кнопкой. Возврат:
// закрывашка, URL для правила и ожидаемый токен (для сверки round-trip'а).
func startSelfPage() (io.Closer, string, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", err
	}
	token := fmt.Sprintf("echo-%d", time.Now().UnixNano())
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<title>echo: своя страница модуля</title>
<body style="font:16px sans-serif;padding:24px">
<h3>Эту страницу отдаёт САМ МОДУЛЬ</h3>
<p>AntiNet о ней ничего не знает — он лишь исполняет правило «поймать переход на
<code>%s</code> и достать параметр <code>token</code>».</p>
<p><a href="%s?token=%s" style="font-size:20px">Подтвердить</a></p>
</body>`, selfPageDonePath, selfPageDonePath, token)
	})
	// Хост перехватывает НАВИГАЦИЮ и закрывает окно сам; обработчик нужен только чтобы переход был
	// валидным, если перехват почему-то не сработал.
	mux.HandleFunc(selfPageDonePath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	return srv, fmt.Sprintf("http://%s/", ln.Addr().String()), token, nil
}

// handleConn — CONNECT-путь модуля: прямой protected-dial и реле. Сам протокол SOCKS5
// (приветствие, авторизация, разбор запроса, реле, UDP ASSOCIATE) — канон shared/socks5,
// инжектируемый build.py при `"socks5": true`; здесь остаётся только то, что у echo своё.
// ЗАМЕНИ d.Dial(...) на свой протокол.
func handleConn(c net.Conn, user, pass, protectPath string, dialTimeout time.Duration, resolver *protectedResolver) {
	defer c.Close()
	br := bufio.NewReader(c)

	req, ok := socksHandshake(c, br, user, pass)
	if !ok {
		return
	}
	if req.Cmd == socksCmdUDPAssociate {
		// UDP ASSOCIATE (RFC 1928 §7) — нужен UDP-каскадам (hysteria2/tuic/wireguard) за echo как
		// основой: без него sing-box получал безусловный `command not supported` и UDP-каскад не
		// поднимался вообще. Отличие от qWDTT архитектурное, не протокольное, и живёт оно ровно в
		// [echoUDPTransport]: у qWDTT дозвон идёт ЧЕРЕЗ его WG-туннель (изоляция от TUN дана самим
		// туннелем), у echo своего туннеля нет — дозвон идёт в реальную сеть и ОБЯЗАН быть
		// protected (тот же dialControl, что защищает TCP CONNECT ниже).
		serveSocksUDPAssociate(c, br, echoUDPTransport{resolver: resolver, protectPath: protectPath})
		return
	}

	host := req.TargetLabel()
	target := net.JoinHostPort(host, strconv.Itoa(int(req.Port)))

	// (2) ПРЯМОЙ dial с protect-fd. Это и есть «passthrough». Свой протокол — здесь.
	//     dialControl: Android — SCM_RIGHTS-protect (иначе сокет лекает в TUN); десктоп — nil (off-TUN
	//     обеспечивает sing-box routing process_name→direct, protect не нужен).
	// ⏱ Таймаут дозвона — НЕ хардкод 15с. Живой замер на устройстве показывает, во что такой потолок
	// обходится: КАЖДЫЙ недостижимый адрес держит соединение ровно 15.0-15.4с, прежде
	// чем модуль ответит `code=1`. На заблокированном в РФ Telegram (149.154.166.121:443/5222) это
	// 25 попыток подряд по 15с в одной выборке — столько же зависших соединений у sing-box и у
	// приложения. Успешные дозвоны при этом укладываются в 9-235мс, то есть длинный таймаут не
	// «страхует медленный сервер», а исключительно затягивает заведомый отказ.
	//
	// Норма ядра — 5с (sing-box `C.TCPTimeout`); passthrough-модуль обязан отказывать так же
	// быстро, тем более что вся политика ретраев живёт ВЫШЕ, в оркестраторе. Значение вынесено в
	// настройку (карточка «Модули»), а не зашито: юзер с реально медленным каналом поднимет.
	//
	// ⏱ Замер РАЗДЕЛЬНО: резолв имени и собственно TCP-дозвон. Иначе `d.Dial("host:port")` прячет
	// внутри себя lookup, и по одной цифре нельзя сказать, где ушли секунды. Симптом, который без
	// этого не разобрать: отклик скачет 256мс ↔ 1787мс, и непонятно, резолв это или дозвон.
	//
	// Резолв идёт через `resolver` (dns.go), НЕ голый `net.DefaultResolver`: тот открывает СВОИ
	// сокеты внутри `LookupHost`, на которые `Control` (висящий на сокете ДОЗВОНА ниже) не попадает —
	// DNS модуля уходило мимо protect'а, в TUN, и крутилось через ЧУЖОЙ DNS-hijack-пайплайн
	// (медленно и зависимо от состояния каскада). `resolver` — protected (dialControl на UDP-запрос
	// к реальному физическому DNS-серверу) + TTL-кэш + single-flight (mirror qWDTT's
	// resolveHostCached — тот же класс, у которого резолв без кэша стоил 5.1-5.4с всплесков).
	dialStart := time.Now()
	lookupMs := 0.0
	dialTarget := target
	if !req.IsIP() {
		ips, lerr := resolver.LookupHost(host)
		lookupMs = float64(time.Since(dialStart).Microseconds()) / 1000.0
		if lerr != nil {
			log.Printf("PERFSPLIT lookup FAILED host=%s lookupElapsed=%.3fms err=%v", host, lookupMs, lerr)
			_, _ = c.Write(socksRep(0x01))
			return
		}
		if len(ips) > 0 {
			dialTarget = net.JoinHostPort(ips[0], strconv.Itoa(int(req.Port)))
		}
		log.Printf("PERFSPLIT lookup OK host=%s ips=%d lookupElapsed=%.3fms", host, len(ips), lookupMs)
	}
	tcpStart := time.Now()
	var pst protectStat // per-dial, не глобал: параллельные дозвоны не смешивают замеры
	d := net.Dialer{Timeout: dialTimeout, Control: dialControl(protectPath, &pst)}
	up, err := d.Dial("tcp", dialTarget)
	tcpMs := float64(time.Since(tcpStart).Microseconds()) / 1000.0
	// protectElapsed входит В tcpDialElapsed (Control зовётся внутри Dial) — «чистый connect»
	// это их разность; печатаем оба, чтобы не считать в уме при разборе лога.
	if err != nil {
		log.Printf("PERFSPLIT tcpDial FAILED host=%s lookupElapsed=%.3fms protectElapsed=%.3fms protectTries=%d protectErr=%q tcpDialElapsed=%.3fms err=%v",
			host, lookupMs, pst.elapsedMs, pst.attempts, pst.firstErr, tcpMs, err)
		_, _ = c.Write(socksRep(0x01)) // general failure
		return
	}
	log.Printf("PERFSPLIT tcpDial OK host=%s lookupElapsed=%.3fms protectElapsed=%.3fms protectTries=%d protectErr=%q tcpDialElapsed=%.3fms totalElapsed=%.3fms",
		host, lookupMs, pst.elapsedMs, pst.attempts, pst.firstErr, tcpMs, float64(time.Since(dialStart).Microseconds())/1000.0)
	defer up.Close()
	if _, err := c.Write(socksRep(0x00)); err != nil {
		return
	}

	// Реле и политика закрытия — канон shared/socks5 (`relayBidi`). Это эталонный модуль, паттерн
	// отсюда расходится по сторонним модулям — тем важнее, что он теперь ОДИН на все модули, а не
	// копия, которую каждый может «поправить» у себя. Полное обоснование (почему ошибку апстрима
	// нельзя выдавать за штатный конец потока и во что это обходилось нашей же классификации
	// отклика) — в доккомментарии самой функции.
	relayBidi(c, br, up, target, dialStart)
}

// echoUDPTransport — реализация канонного [socksUDPTransport] для echo: чем модуль резолвит и чем
// дозванивается до цели UDP-датаграммы. Сам реле-цикл (bind loopback, BND-ответ, дренаж
// control-conn'а, кэш per-target, обёртка ответов, счётчики) — канон shared/socks5. Своя копия
// этого цикла обычно выходит беднее: без assocID, без счётчиков пакетов/байт и без `readyCh`
// (гонка «первый пакет ушёл раньше, чем приёмная горутина встала в Read»).
//
// Архитектурное отличие от qWDTT живёт ровно здесь и больше нигде: у qWDTT дозвон идёт ЧЕРЕЗ его
// WG-туннель (изоляция от TUN дана самим туннелем), у echo своего туннеля нет — дозвон идёт
// напрямую в реальную сеть и ОБЯЗАН быть protected, иначе UDP-пакеты каскад-сервера уйдут в TUN и
// зациклятся. Loopback-relay канона protect не нужен — TUN его не ловит.
type echoUDPTransport struct {
	resolver    *protectedResolver
	protectPath string
}

func (t echoUDPTransport) LookupHost(host string) ([]string, error) {
	return t.resolver.LookupHost(host)
}

func (t echoUDPTransport) DialUDPTarget(dst netip.AddrPort) (net.Conn, error) {
	// protectStat — per-dial, не глобал: параллельные дозвоны не смешивают замеры. Метрики уходят
	// В ТЕКСТ ошибки, а не отдельной лог-строкой: логирует исход канон, и своя строка рядом с его
	// строкой означала бы две записи об одном событии.
	var pst protectStat
	d := net.Dialer{Control: dialControl(t.protectPath, &pst)}
	nc, err := d.Dial("udp", dst.String())
	if err != nil {
		return nil, fmt.Errorf("protectElapsed=%.3fms protectTries=%d protectErr=%q: %w",
			pst.elapsedMs, pst.attempts, pst.firstErr, err)
	}
	return nc, nil
}

// relayCopy — как io.Copy(dst, src), но раздельно возвращает ошибку ЧТЕНИЯ из src (апстрим) и ошибку
// ЗАПИСИ в dst (клиент). `io.Copy` их не различает (одна error на обе стороны), а именно это различие
// и определяет, чем закрывать клиентское соединение: обрыв туннеля обязан выглядеть обрывом, штатный
// уход клиента — ничем. io.EOF — не ошибка: это и есть корректный конец потока.
// relayCopy / readLenPrefixed / readAddr / replyOK / replyErr — теперь канон shared/socks5
// (`relayCopy`, `socksReadLP`, разбор внутри `socksHandshake`, `socksRep`).
//
// Все пять были копиями: `relayCopy` совпадал с qWDTT'шным байт-в-байт; `readLenPrefixed` — то же
// тело, что `socksReadLP`, под другим именем; а `replyErr` был байт-в-байт равен `socksRep` из
// канона, который этому же модулю УЖЕ инжектировался — то есть в одном пакете лежали две копии
// одной функции.
