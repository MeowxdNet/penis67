// penis67 plugin — AntiNet module serving penis67:// links (P67 stealth
// tunnel: REALITY-class TLS camouflage with uTLS fingerprints).
//
// Android: c-shared .so exporting antinet_module_run/_event/_call/_free.
// Desktop: executable, argv[1] = KEY=VALUE config file.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
	"unsafe"

	/*
		#include <stdlib.h>
	*/
	"C"

	"net.meowxd.modcommon/engines"
	"net.meowxd.modcommon/modhost"

	p67 "net.meowxd.plugin.penis67/internal/p67"
)

var (
	stateMu   sync.Mutex
	runCancel context.CancelFunc
	runDone   chan struct{}
)

func logAdapter(control *modhost.Control) func(string) {
	return func(message string) { control.Log("%s", message) }
}

func runModule(ctx context.Context, cfg *modhost.Config, profileDir, protectPath string, control *modhost.Control) error {
	if cfg.Link == "" || cfg.ListenPort == "" {
		return fmt.Errorf("p67: incomplete module config")
	}
	port, err := strconv.Atoi(cfg.ListenPort)
	if err != nil {
		return fmt.Errorf("p67: bad LISTEN_PORT %q", cfg.ListenPort)
	}
	link, err := p67.Parse(cfg.Link)
	if err != nil {
		control.Log("link rejected: %v", err)
		return err
	}
	control.Status("engine p67 starting (%s)", link.Name)

	protect := modhost.NewProtect(protectPath)
	dialer := modhost.NewDialer(protect)
	dialer.Resolver = modhost.ProtectedResolver(protect, cfg.DNSServers)

	engine := p67.NewEngine(link, dialer, logAdapter(control))
	front, err := engines.NewSOCKS5Front(port, engine, cfg.SOCKSUser, cfg.SOCKSPass, logAdapter(control))
	if err != nil {
		return fmt.Errorf("socks5 bind: %w", err)
	}
	if err := control.Ready(); err != nil {
		front.Close()
		return fmt.Errorf("ready marker: %w", err)
	}
	control.Status("ready on 127.0.0.1:%d (penis67)", port)

	serveErr := make(chan error, 1)
	go func() { serveErr <- front.Serve() }()
	select {
	case err := <-serveErr:
		_ = engine.Close()
		return err
	case <-ctx.Done():
		_ = front.Close()
		_ = engine.Close()
		return nil
	}
}

func moduleEvent(line string) {
	if line == "stop" {
		stateMu.Lock()
		cancel := runCancel
		stateMu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
}

//export antinet_module_run
func antinet_module_run(config *C.char, resolverPath *C.char, dir *C.char, protectPath *C.char, listenFD C.int) C.int {
	_ = listenFD
	cfg := modhost.ParseConfig(C.GoString(config))
	for _, resolver := range modhost.ResolverFile(C.GoString(resolverPath)) {
		cfg.DNSServers = append(cfg.DNSServers, resolver)
	}
	control := modhost.NewControl(C.GoString(dir))
	ctx, cancel := context.WithCancel(context.Background())
	stateMu.Lock()
	runCancel = cancel
	runDone = make(chan struct{})
	stateMu.Unlock()
	go func() {
		defer close(runDone)
		if err := runModule(ctx, cfg, C.GoString(dir), C.GoString(protectPath), control); err != nil {
			control.Log("module exiting: %v", err)
			os.Exit(1)
		}
	}()
	<-runDone
	return 0
}

//export antinet_module_event
func antinet_module_event(line *C.char) {
	if line != nil {
		moduleEvent(C.GoString(line))
	}
}

//export antinet_module_call
func antinet_module_call(verb *C.char, arg *C.char) *C.char {
	answer := ""
	switch C.GoString(verb) {
	case "summarize":
		answer = p67.Summarize(C.GoString(arg))
	case "normalize":
		answer = ""
	case "canping":
		answer = "1"
	}
	return (*C.char)(C.CString(answer))
}

//export antinet_module_free
func antinet_module_free(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

func main() {
	if len(os.Args) >= 5 {
		configData, err := os.ReadFile(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(65)
		}
		cfg := modhost.ParseConfig(string(configData))
		for _, resolver := range modhost.ResolverFile(os.Args[2]) {
			cfg.DNSServers = append(cfg.DNSServers, resolver)
		}
		control := modhost.NewControl(os.Args[3])
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				moduleEvent(scanner.Text())
			}
		}()
		go func() {
			if err := runModule(ctx, cfg, os.Args[3], os.Args[4], control); err != nil {
				control.Log("module exiting: %v", err)
				os.Exit(1)
			}
		}()
		for {
			time.Sleep(time.Hour)
		}
	}
	fmt.Fprintln(os.Stderr, "penis67 plugin (penis67://)")
	fmt.Fprintln(os.Stderr, "android: dlopen'ed by the meow module host")
	fmt.Fprintln(os.Stderr, "desktop: penis67-plugin <config> <resolvers> <profileDir> <protectPath>")
	os.Exit(64)
}
