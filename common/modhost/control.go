package modhost

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Control is the module's stdout channel to the host (MODULE_API §2.9):
// every marker line is timestamp-prefixed and the host matches markers by
// substring, so extra prefixes never break parsing.
type Control struct {
	mu         sync.Mutex
	out        *os.File
	profileDir string
}

// NewControl wires the control channel. stdout is shared with nothing else:
// the module logs exclusively through it.
func NewControl(profileDir string) *Control {
	return &Control{out: os.Stdout, profileDir: profileDir}
}

func (c *Control) write(marker, text string) {
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) > 4096 {
		text = text[:4096] + "…"
	}
	line := time.Now().UTC().Format(time.RFC3339) + " " + marker + text + "\n"
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = c.out.WriteString(line)
}

// Log emits a LOG| line (visible in the module's log slice).
func (c *Control) Log(format string, args ...any) {
	c.write("LOG|", fmt.Sprintf(format, args...))
}

// Status emits a STATUS| line (short lifecycle state change).
func (c *Control) Status(format string, args ...any) {
	c.write("STATUS|", fmt.Sprintf(format, args...))
}

// Progress emits a PROGRESS| line (connect progress text).
func (c *Control) Progress(format string, args ...any) {
	c.write("PROGRESS|", fmt.Sprintf(format, args...))
}

// SaveState hands the host a base64 blob to persist in the durable profile
// (MODULE_API §2.3); the next start receives it back as MODULE_STATE.
func (c *Control) SaveState(blob []byte) {
	if len(blob) == 0 || len(blob) > 768*1024 {
		return
	}
	c.write("STATE_SAVE|", base64.StdEncoding.EncodeToString(blob))
}

// ActionRequest asks the host to render an interactive action (MODULE_API
// §2.7). The payload is JSON; `id` must stay unique among pending actions.
// The answer arrives through the event channel as ACTION_RESULT|id|<b64>.
func (c *Control) ActionRequest(id, jsonPayload string) {
	c.write("ACTION_REQUIRED|"+id+"|", jsonPayload)
}

// ActionClose withdraws a pending action (e.g. the flow resolved itself).
func (c *Control) ActionClose(id string) {
	c.write("ACTION_CLOSE|", id)
}

// AckEvent confirms a host event was processed (MODULE_API §2.8).
func (c *Control) AckEvent(event string) {
	c.write("EVENT_ACK|", event)
}

// Ready writes the readiness marker into the durable profile directory the
// host handed us. The core unblocks the outbound only once it appears, so it
// must be written exactly when the module can serve its first SOCKS5 dial.
func (c *Control) Ready() error {
	if c.profileDir == "" {
		return fmt.Errorf("no profile directory")
	}
	if err := os.MkdirAll(c.profileDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.profileDir, "ready"), []byte("ready\n"), 0o600)
}

// StateFile is the path of a state blob the host persisted for us.
func (c *Control) StateFile() string {
	if c.profileDir == "" {
		return ""
	}
	return filepath.Join(c.profileDir, "state.b64")
}
