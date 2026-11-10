// SPDX-License-Identifier: MIT

// penis67 helper — SOCKS5-фронт на сокете, который создаёт и передаёт хост
// (§2.6), туннель REALITY-класса до P67-сервера. Транспорт — канон
// shared/socks5; протокол — internal/p67 (sid-маркер, decoy-relay, mux).
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"p67helper/internal/p67"
)

// realMain — тело модуля (MODULE_API §2.3): точка входа — канон shared/entry
// (antinet_module_run / argv), он вызывает ЭТУ функцию и ждёт от неё кода
// выхода. Блокирует до конца жизни модуля.
//
// ⏱ Таймауты — не хардкод: недостижимый адрес не должен держать соединение
// приложения по 15с (замер echo: 25 зависаний по 15с на одном адресе).
// Значения живут в настройках карточки «Модули» (SETTING_dialTimeoutSec и
// SETTING_dialTimeoutCarrierSec), дефолты — в module.json.
func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	cfg := parseConfig(configContent)

	port, perr := strconv.Atoi(cfg["LISTEN_PORT"])
	if perr != nil || port <= 0 {
		emitLog("хост не прислал LISTEN_PORT: %q", cfg["LISTEN_PORT"])
		emitStatus(statusFatal, "bad listen port")
		return 1
	}
	link, err := p67.Parse(cfg["LINK"])
	if err != nil {
		// §2.13: LOG| читает юзер (русская строка по APP_LANG), STATUS| — хост.
		emitLog("ссылка penis67 не разобрана: %v", err)
		emitStatus(statusFatal, "bad link")
		return 1
	}

	dialTimeoutSec := settingSeconds(cfg, "dialTimeoutSec", 5)
	carrierTimeout := settingSeconds(cfg, "dialTimeoutCarrierSec", 15)
	dialTimeout := time.Duration(dialTimeoutSec) * time.Second
	carrier := time.Duration(carrierTimeout) * time.Second

	resolver := newProtectedResolver(cfg["DNS_SERVERS"], protectPath)
	dialer := protectedDialer(protectPath, carrier)

	engine := p67.NewEngine(link, &p67.Dialer{
		DialContext: dialer.dial,
		ListenUDP:   dialer.listenUDP,
	}, func(message string) { emitLog("%s", message) })

	// Слушающий сокет — ХОСТОВ (§2.6): усыновляем fd (Android-слот) или
	// биндим присланный порт (Windows/старый хост). Свой bind — это тот
	// самый EADDRINUSE, из-за которого модули вылетают до ready.
	ln, err := openListener(port, listenFd)
	if err != nil {
		emitLog("не удалось принять слушающий сокет: %v", err)
		emitStatus(statusFatal, "socks bind failed")
		return 1
	}

	// Маркер готовности — канон shared/lifecycle: атомарно, fatal при ошибке
	// (без него хост досидит до своего READY_TIMEOUT без причины в логе).
	if err := writeReady(profileDir, port); err != nil {
		emitLog("не удалось записать маркер готовности: %v", err)
		emitStatus(statusFatal, "write ready marker failed")
		return 1
	}
	emitProgress("penis67: SOCKS5 поднят на 127.0.0.1:%d (носитель %s, decoy %s)", port, link.Net, link.Decoy)
	emitStatus(statusOK, "")

	transport := p67UDPTransport{
		engine:   engine,
		resolver: resolver,
		dialer:   dialer,
	}
	_ = dialTimeoutSec

	// Accept-петля — канон shared/socks5: транзиентная ошибка её не роняет.
	serveSocksListener(ln, func(c net.Conn) {
		handleConn(c, cfg["SOCKS_USER"], cfg["SOCKS_PASS"], engine, transport,
			resolver, protectPath, dialTimeout)
	})
	return 0
}

// handleConn — CONNECT/UDP ASSOCIATE-путь: разбор каноном shared/socks5,
// транспорт — стримы P67-туннеля. Домен цели уходит на сервер как есть
// (резолв на выходном узле), локально резолвится только декой/носитель.
func handleConn(c net.Conn, user, pass string, engine *p67.Engine,
	transport p67UDPTransport, resolver *protectedResolver, protectPath string,
	dialTimeout time.Duration) {
	defer c.Close()
	br := bufio.NewReader(c)

	req, ok := socksHandshake(c, br, user, pass)
	if !ok {
		return
	}
	if req.Cmd == socksCmdUDPAssociate {
		serveSocksUDPAssociate(c, br, transport)
		return
	}

	target := net.JoinHostPort(req.TargetLabel(), strconv.Itoa(int(req.Port)))
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	up, err := engine.DialContext(ctx, "tcp", target)
	if err != nil {
		emitLog("цель недостижима через туннель: %v", err)
		_, _ = c.Write(socksRep(0x01))
		return
	}
	defer up.Close()
	if _, err := c.Write(socksRep(0x00)); err != nil {
		return
	}
	// Реле и политика закрытия — канон shared/socks5 (relayBidi): обрыв
	// туннеля выглядит обрывом, штатный уход клиента — ничем.
	relayBidi(c, br, up, target, time.Now())
}

// p67UDPTransport — реализация канонного [socksUDPTransport]: чем модуль
// резолвит и дозванивается до цели UDP-датаграммы. Реле-цикл (bind
// loopback, BND-ответ, дренаж control-conn'а, per-target кэш) — канон
// shared/socks5; дозвон ОБЯЗАН быть protected, иначе UDP уйдёт в TUN.
type p67UDPTransport struct {
	engine   *p67.Engine
	resolver *protectedResolver
	dialer   dialerSet
}

func (t p67UDPTransport) LookupHost(host string) ([]string, error) {
	return t.resolver.LookupHost(host)
}

func (t p67UDPTransport) DialUDPTarget(dst netip.AddrPort) (net.Conn, error) {
	pc, err := t.engine.PacketConn(context.Background(), dst.String())
	if err != nil {
		return nil, err
	}
	remote := net.UDPAddrFromAddrPort(dst)
	return &packetConnAsConn{pc: pc, remote: remote}, nil
}

// packetConnAsConn представляет датаграммный стрим как net.Conn для канона
// UDP ASSOCIATE: Read/Write двигают по одной датаграмме.
type packetConnAsConn struct {
	pc     net.PacketConn
	remote net.Addr
}

func (p *packetConnAsConn) Read(b []byte) (int, error) {
	n, _, err := p.pc.ReadFrom(b)
	return n, err
}

func (p *packetConnAsConn) Write(b []byte) (int, error) {
	return p.pc.WriteTo(b, nil)
}

func (p *packetConnAsConn) Close() error                       { return p.pc.Close() }
func (p *packetConnAsConn) LocalAddr() net.Addr                { return p.remote }
func (p *packetConnAsConn) RemoteAddr() net.Addr               { return p.remote }
func (p *packetConnAsConn) SetDeadline(t time.Time) error      { return p.pc.SetDeadline(t) }
func (p *packetConnAsConn) SetReadDeadline(t time.Time) error  { return p.pc.SetReadDeadline(t) }
func (p *packetConnAsConn) SetWriteDeadline(t time.Time) error { return p.pc.SetWriteDeadline(t) }

// ── Настройки и защищённый дозвон ─────────────────────────────────────────────

// settingSeconds — целочисленная настройка SETTING_<key> (сек) с дефолтом.
func settingSeconds(cfg map[string]string, key string, def int) int {
	raw := strings.TrimSpace(cfg["SETTING_"+key])
	if raw == "" {
		return def
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return n
	}
	return def
}

// dialerSet — защищённые дозвон и UDP-листенер носителя.
type dialerSet struct {
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	listenUDP func(ctx context.Context) (*net.UDPConn, error)
}

// protectedDialer — все сокеты носителя через protect-контроль хоста
// (Android: SCM_RIGHTS-protect; десктоп: bind к физическому адаптеру),
// иначе носитель лекает в TUN и зацикливается.
func protectedDialer(protectPath string, carrierTimeout time.Duration) dialerSet {
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var pst protectStat
		d := net.Dialer{Timeout: carrierTimeout, Control: dialControl(protectPath, &pst)}
		return d.DialContext(ctx, network, address)
	}
	listenUDP := func(ctx context.Context) (*net.UDPConn, error) {
		var pst protectStat
		lc := net.ListenConfig{Control: dialControl(protectPath, &pst)}
		pc, err := lc.ListenPacket(ctx, "udp", ":0")
		if err != nil {
			return nil, err
		}
		udp, ok := pc.(*net.UDPConn)
		if !ok {
			_ = pc.Close()
			return nil, fmt.Errorf("listen packet: not a UDP socket")
		}
		return udp, nil
	}
	return dialerSet{dial: dial, listenUDP: listenUDP}
}

// moduleCall — parse-only сабкоманды (§2.2): summarize (карточка ссылки),
// normalize, canping. Обслуживаются точкой входа ДО любой тяжёлой обвязки.
func moduleCall(verb, arg string) string {
	switch verb {
	case "summarize":
		return p67.Summarize(arg)
	case "normalize":
		return ""
	case "canping":
		return "1"
	}
	return ""
}
