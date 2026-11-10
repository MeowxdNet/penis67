// penis67 share links:
//
//	penis67://<uuid>@host:port?fp=chrome&hide=sid&sni=www.bing.com&pbk=<b64url>&dpy=&dport=&frag=&fragd=&pad=1#name
//
//	- uuid — 8-4-4-4-12 (or 32 hex) user key, VLESS-style;
//	- fp — uTLS fingerprint: chrome (default), firefox, safari, ios,
//	  android, edge, random, mixed (rotates per connection);
//	- hide — marker carrier: sid (default) hides the auth inside the
//	  legacy_session_id + the handshake's own X25519 share — zero
//	  non-browser bytes in the ClientHello; ext uses the 0x2F47 extension;
//	- sni — ServerName in the ClientHello (default: host);
//	- pbk — server static X25519 public key, base64url (required);
//	- dpy — decoy site the server relays unauthorized traffic to
//	  (default: sni);
//	- dport — decoy port (default 443);
//	- frag — split the ClientHello into TCP segments of ≤N bytes
//	  (0 = off, default);
//	- fragd — delay between fragments, milliseconds (default 20);
//	- ech — allow the (GREASE-)ECH extension in the fingerprint; off by
//	  default because ECH is throttled in some networks (e.g. RU);
//	- pad — padding frames on/off (default on).
package p67

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Link is a decoded penis67:// share link.
type Link struct {
	User         UserKey
	Host         string
	Port         int
	Fingerprint  string
	Hide         string // "sid" (default) or "ext"
	SNI          string
	PBK          string // base64url X25519 static public key
	Decoy        string
	DecoyPort    int
	Frag         int // ClientHello TCP fragmentation size, 0 = off
	FragDelay    int // fragment delay, ms
	AllowECH     bool
	Pad          bool
	Net          string // "tcp" (default) or "quic" carrier
	RTT0         bool   // pipeline the first stream into the auth flight
	MultiCarrier int    // parallel carrier connections, 1..4 (default 1)
	Name         string
}

// DefaultPort is the assumed port when the link omits one.
const DefaultPort = 443

// Carrier names for hide= and net=.
const (
	HideSID = "sid"
	HideExt = "ext"
	NetTCP  = "tcp"
	NetQUIC = "quic"
)

// FingerprintNames lists the accepted fp= values.
var FingerprintNames = []string{"chrome", "firefox", "safari", "ios", "android", "edge", "random", "mixed"}

// Parse decodes and validates a penis67:// link.
func Parse(link string) (*Link, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return nil, fmt.Errorf("p67: bad link: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "penis67") {
		return nil, fmt.Errorf("p67: bad scheme %q", u.Scheme)
	}
	out := &Link{}
	if raw := u.User.Username(); raw != "" {
		user, err := ParseUUID(raw)
		if err != nil {
			return nil, err
		}
		out.User = user
	} else {
		return nil, fmt.Errorf("p67: missing uuid")
	}
	out.Host = u.Hostname()
	if out.Host == "" {
		return nil, fmt.Errorf("p67: missing host")
	}
	if port, err := strconv.Atoi(u.Port()); err == nil && port != 0 {
		out.Port = port
	} else {
		out.Port = DefaultPort
	}
	values := u.Query()

	out.Fingerprint = strings.ToLower(values.Get("fp"))
	if out.Fingerprint == "" {
		out.Fingerprint = "chrome"
	}
	if !fingerprintKnown(out.Fingerprint) {
		return nil, fmt.Errorf("p67: bad fp=%q (want one of %s)",
			values.Get("fp"), strings.Join(FingerprintNames, ", "))
	}

	out.Hide = strings.ToLower(values.Get("hide"))
	if out.Hide == "" {
		out.Hide = HideSID
	}
	if out.Hide != HideSID && out.Hide != HideExt {
		return nil, fmt.Errorf("p67: bad hide=%q (want sid or ext)", values.Get("hide"))
	}

	out.SNI = values.Get("sni")
	if out.SNI == "" {
		out.SNI = out.Host
	}
	out.PBK = values.Get("pbk")
	if out.PBK == "" {
		return nil, fmt.Errorf("p67: missing pbk (server static public key)")
	}
	if _, err := DecodePublicKey(out.PBK); err != nil {
		return nil, err
	}
	out.Decoy = values.Get("dpy")
	if out.Decoy == "" {
		out.Decoy = out.SNI
	}
	out.DecoyPort = 443
	if v := values.Get("dport"); v != "" {
		if port, err := strconv.Atoi(v); err == nil && port > 0 && port < 65536 {
			out.DecoyPort = port
		} else {
			return nil, fmt.Errorf("p67: bad dport=%q", v)
		}
	}
	out.Frag = 0
	if v := values.Get("frag"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 1000 {
			out.Frag = n
		} else {
			return nil, fmt.Errorf("p67: bad frag=%q (0..1000)", v)
		}
	}
	out.FragDelay = 20
	if v := values.Get("fragd"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 500 {
			out.FragDelay = n
		} else {
			return nil, fmt.Errorf("p67: bad fragd=%q (0..500)", v)
		}
	}
	if v := strings.ToLower(values.Get("ech")); v == "1" || v == "true" || v == "on" {
		out.AllowECH = true
	}
	out.Net = NetTCP
	if v := strings.ToLower(values.Get("net")); v != "" {
		if v != NetTCP && v != NetQUIC {
			return nil, fmt.Errorf("p67: bad net=%q (want tcp or quic)", values.Get("net"))
		}
		out.Net = v
	}
	if v := strings.ToLower(values.Get("rtt0")); v == "1" || v == "true" || v == "on" {
		out.RTT0 = true
	}
	out.MultiCarrier = 1
	if v := values.Get("mc"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 4 {
			out.MultiCarrier = n
		} else {
			return nil, fmt.Errorf("p67: bad mc=%q (1..4)", v)
		}
	}
	out.Pad = true
	if v := strings.ToLower(values.Get("pad")); v == "0" || v == "false" || v == "off" {
		out.Pad = false
	}
	if fragment, err := url.PathUnescape(u.Fragment); err == nil && fragment != "" {
		out.Name = fragment
	} else {
		out.Name = u.Fragment
	}
	if out.Name == "" {
		out.Name = out.Host
	}
	return out, nil
}

func fingerprintKnown(name string) bool {
	for _, known := range FingerprintNames {
		if known == name {
			return true
		}
	}
	return false
}

// Build renders the canonical share link for the values it knows.
func (l *Link) Build() string {
	var b strings.Builder
	b.WriteString("penis67://")
	b.WriteString(l.User.FormatUUID())
	b.WriteString("@")
	b.WriteString(net.JoinHostPort(l.Host, strconv.Itoa(l.Port)))
	b.WriteString("?fp=")
	b.WriteString(l.Fingerprint)
	if l.Hide != HideSID {
		b.WriteString("&hide=")
		b.WriteString(l.Hide)
	}
	b.WriteString("&sni=")
	b.WriteString(url.QueryEscape(l.SNI))
	b.WriteString("&pbk=")
	b.WriteString(l.PBK)
	if l.Decoy != l.SNI {
		b.WriteString("&dpy=")
		b.WriteString(url.QueryEscape(l.Decoy))
	}
	if l.DecoyPort != 443 {
		b.WriteString("&dport=")
		b.WriteString(strconv.Itoa(l.DecoyPort))
	}
	if l.Frag > 0 {
		b.WriteString("&frag=")
		b.WriteString(strconv.Itoa(l.Frag))
		if l.FragDelay != 20 {
			b.WriteString("&fragd=")
			b.WriteString(strconv.Itoa(l.FragDelay))
		}
	}
	if l.AllowECH {
		b.WriteString("&ech=1")
	}
	if l.Net != NetTCP {
		b.WriteString("&net=")
		b.WriteString(l.Net)
	}
	if l.RTT0 {
		b.WriteString("&rtt0=1")
	}
	if l.MultiCarrier > 1 {
		b.WriteString("&mc=")
		b.WriteString(strconv.Itoa(l.MultiCarrier))
	}
	if !l.Pad {
		b.WriteString("&pad=0")
	}
	b.WriteString("#")
	b.WriteString(url.PathEscape(l.Name))
	return b.String()
}

// Address is the server endpoint the engine dials.
func (l *Link) Address() string {
	return net.JoinHostPort(l.Host, strconv.Itoa(l.Port))
}

// DecoyAddress is where the server relays unauthorized connections.
func (l *Link) DecoyAddress() string {
	return net.JoinHostPort(l.Decoy, strconv.Itoa(l.DecoyPort))
}

// Summarize renders the module card lines for a link.
func Summarize(link string) string {
	parsed, err := Parse(link)
	if err != nil {
		return ""
	}
	lines := []string{
		parsed.Name,
		parsed.Address(),
		"penis67 / stealth-tls",
		"fp " + parsed.Fingerprint,
		"hide " + parsed.Hide,
	}
	if parsed.Net != NetTCP {
		lines = append(lines, "net "+parsed.Net)
	}
	if parsed.Pad {
		lines = append(lines, "pad on")
	}
	if parsed.Frag > 0 {
		lines = append(lines, "frag "+strconv.Itoa(parsed.Frag))
	}
	if parsed.MultiCarrier > 1 {
		lines = append(lines, "mc "+strconv.Itoa(parsed.MultiCarrier))
	}
	return strings.Join(lines, "\n")
}
