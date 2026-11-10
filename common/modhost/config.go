// Package modhost implements the client side of the AntiNet MODULE_API (v1)
// contract the meow client's sing-box core speaks to plugin modules:
//
//   - the KEY=VALUE config the host passes base64-encoded (Android) or as a
//     plain file (desktop) in ANTINET_MODULE_CONFIG,
//   - the control protocol on stdout (LOG|, STATUS|, PROGRESS|, STATE_SAVE|,
//     ACTION_REQUIRED|, ACTION_CLOSE|, EVENT_ACK| — all timestamp-prefixed),
//   - the `ready` marker file in the durable profile directory,
//   - host events arriving on stdin ("stop", "handover", "dns=…"),
//   - the Android socket protect service (SCM_RIGHTS over a unix socket).
//
// The module process model: the core spawns the module host with the module
// shared library, waits for <profileDir>/ready for up to 95 s, then dials the
// module's SOCKS5 endpoint on 127.0.0.1:LISTEN_PORT with SOCKS_USER/SOCKS_PASS
// credentials. Everything in this package exists to serve that lifecycle.
package modhost

import (
	"os"
	"strconv"
	"strings"
)

// Config is the decoded ANTINET_MODULE_CONFIG payload. Values are single-line
// KEY=VALUE pairs; see sing-box protocol/plugin/process.go moduleConfig.text().
type Config struct {
	Link          string // the imported share link, verbatim
	ListenPort    string // SOCKS5 listen port on 127.0.0.1
	SOCKSUser     string
	SOCKSPass     string
	AppLang       string
	DNSServers    []string // physical-network resolvers, comma separated
	HostFeatures  string   // comma separated webview.* tokens the host implements
	DeviceID      string
	StartReason   string // cold | resume | handover
	ModuleState   string // base64 blob saved by an earlier STATE_SAVE
	RelayWindowSec int
	Settings      map[string]string // SETTING_<key> entries, lower-cased keys
}

// Value returns the raw config value for a SETTING key.
func (c *Config) Setting(key string) string {
	if c.Settings == nil {
		return ""
	}
	return c.Settings[key]
}

// ParseConfig decodes the KEY=VALUE text. Unknown keys are ignored so newer
// hosts keep working with older modules.
func ParseConfig(text string) *Config {
	cfg := &Config{Settings: map[string]string{}}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "LINK":
			cfg.Link = value
		case "LISTEN_PORT":
			cfg.ListenPort = value
		case "SOCKS_USER":
			cfg.SOCKSUser = value
		case "SOCKS_PASS":
			cfg.SOCKSPass = value
		case "APP_LANG":
			cfg.AppLang = value
		case "DNS_SERVERS":
			for _, dns := range strings.Split(value, ",") {
				dns = strings.TrimSpace(dns)
				if dns != "" {
					cfg.DNSServers = append(cfg.DNSServers, dns)
				}
			}
		case "HOST_FEATURES":
			cfg.HostFeatures = value
		case "DEVICE_ID":
			cfg.DeviceID = value
		case "START_REASON":
			cfg.StartReason = value
		case "MODULE_STATE":
			cfg.ModuleState = value
		case "RELAY_WINDOW_SEC":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.RelayWindowSec = n
			}
		default:
			if setting, found := strings.CutPrefix(key, "SETTING_"); found {
				cfg.Settings[strings.ToLower(setting)] = value
			}
		}
	}
	return cfg
}

// HostFeature reports whether the host advertised [token] (MODULE_API §2.7).
func (c *Config) HostFeature(token string) bool {
	for _, feature := range strings.Split(c.HostFeatures, ",") {
		if strings.TrimSpace(feature) == token {
			return true
		}
	}
	return false
}

// ResolverFile reads the resolvers file the host stages next to the config.
// The file carries one resolver per line; it may be empty or missing.
func ResolverFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
