package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const version = "1.0.0"

type Config struct {
	Server          string
	EnrollmentToken string
	AgentToken      string
	AgentID         string
	CAFile          string
}

func configPath() string {
	if p := os.Getenv("CYBER_AGENT_CONFIG"); p != "" {
		return p
	}
	switch runtime.GOOS {
	case "windows":
		return "C:\\ProgramData\\CybersecurityAgent\\agent.json"
	case "darwin":
		return "/Library/Application Support/CybersecurityAgent/agent.json"
	default:
		return "/etc/cybersecurity-agent/agent.json"
	}
}

func loadConfig() (Config, error) {
	var c Config
	b, err := os.ReadFile(configPath())
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func saveConfig(c Config) error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(p, b, 0600)
}

func httpClient(c Config) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("invalid CA file")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func post(c Config, path string, payload any, token string) ([]byte, error) {
	client, err := httpClient(c)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", strings.TrimRight(c.Server, "/")+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Agent-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return body, fmt.Errorf("server status %s: %s", resp.Status, string(body))
	}
	return body, nil
}

func command(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	s := string(out)
	if len(s) > 12000 {
		s = s[:12000]
	}
	return s
}

func inventory() map[string]string {
	host, _ := os.Hostname()
	u, _ := user.Current()
	osVersion := ""

	switch runtime.GOOS {
	case "windows":
		osVersion = command("cmd", "/c", "ver")
	case "darwin":
		osVersion = command("sw_vers", "-productVersion")
	default:
		osVersion = command("sh", "-c", "awk -F= '/^PRETTY_NAME=/{gsub(/^PRETTY_NAME=/,\"\");gsub(/^\"|\"$/,\"\");print}' /etc/os-release")
	}

	username := ""
	if u != nil {
		username = u.Username
	}

	return map[string]string{
		"hostname":   host,
		"username":   username,
		"os_version": strings.TrimSpace(osVersion),
	}
}

func enroll(c *Config) error {
	inv := inventory()
	payload := map[string]string{
		"enrollment_token": c.EnrollmentToken,
		"hostname":         inv["hostname"],
		"platform":         runtime.GOOS,
		"architecture":     runtime.GOARCH,
		"os_version":       inv["os_version"],
		"username":         inv["username"],
		"agent_version":    version,
	}
	b, err := post(*c, "/api/agent/enroll", payload, "")
	if err != nil {
		return err
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	c.AgentID = out["agent_id"]
	c.AgentToken = out["agent_token"]
	c.EnrollmentToken = ""
	return saveConfig(*c)
}

func processSnapshot() string {
	switch runtime.GOOS {
	case "windows":
		return command("powershell", "-NoProfile", "-Command",
			"Get-Process | Select-Object -First 80 Id,ProcessName,Path | ConvertTo-Json -Compress")
	case "darwin":
		return command("ps", "-axo", "pid,ppid,user,comm")
	default:
		return command("ps", "-eo", "pid,ppid,user,comm,args", "--no-headers")
	}
}

func networkSnapshot() string {
	switch runtime.GOOS {
	case "windows":
		return command("powershell", "-NoProfile", "-Command",
			"Get-NetTCPConnection -State Established | Select-Object -First 80 LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress")
	case "darwin":
		return command("netstat", "-an")
	default:
		return command("ss", "-tunap")
	}
}

func collectSnapshot() []map[string]any {
	return []map[string]any{
		{
			"event_type": "PROCESS",
			"severity":   "INFO",
			"title":      "Process snapshot",
			"details":    "Periodic endpoint process snapshot",
			"data":       map[string]any{"snapshot": processSnapshot()},
		},
		{
			"event_type": "NETWORK",
			"severity":   "INFO",
			"title":      "Network snapshot",
			"details":    "Periodic active connection snapshot",
			"data":       map[string]any{"snapshot": networkSnapshot()},
		},
	}
}

func heartbeat(c Config) error {
	inv := inventory()
	payload := map[string]any{
		"username":      inv["username"],
		"os_version":    inv["os_version"],
		"architecture":  runtime.GOARCH,
		"agent_version": version,
		"telemetry":     map[string]any{"goos": runtime.GOOS},
	}
	_, err := post(c, "/api/agent/heartbeat", payload, c.AgentToken)
	return err
}

func sendEvents(c Config, events []map[string]any) error {
	_, err := post(c, "/api/agent/events", events, c.AgentToken)
	return err
}

func main() {
	server := flag.String("server", "", "controller URL, for example https://10.0.0.10:8443")
	enrollmentToken := flag.String("enroll", "", "one-time enrollment token")
	ca := flag.String("ca", "", "controller CA certificate")
	once := flag.Bool("once", false, "send one heartbeat and telemetry snapshot, then exit")
	flag.Parse()

	c, err := loadConfig()
	if err != nil {
		if *server == "" || *enrollmentToken == "" {
			fmt.Fprintln(os.Stderr, "configuration not found; supply --server and --enroll")
			os.Exit(2)
		}
		c = Config{
			Server:          *server,
			EnrollmentToken: *enrollmentToken,
			CAFile:          *ca,
		}
		if err := saveConfig(c); err != nil {
			panic(err)
		}
	}

	if c.AgentToken == "" {
		if err := enroll(&c); err != nil {
			fmt.Fprintln(os.Stderr, "enrollment:", err)
			os.Exit(3)
		}
	}

	runOnce := func() {
		if err := heartbeat(c); err != nil {
			fmt.Fprintln(os.Stderr, "heartbeat:", err)
		}
		if err := sendEvents(c, collectSnapshot()); err != nil {
			fmt.Fprintln(os.Stderr, "events:", err)
		}
	}

	runOnce()
	if *once {
		return
	}

	heartbeatTicker := time.NewTicker(30 * time.Second)
	snapshotTicker := time.NewTicker(2 * time.Minute)
	defer heartbeatTicker.Stop()
	defer snapshotTicker.Stop()

	for {
		select {
		case <-heartbeatTicker.C:
			if err := heartbeat(c); err != nil {
				fmt.Fprintln(os.Stderr, "heartbeat:", err)
			}
		case <-snapshotTicker.C:
			if err := sendEvents(c, collectSnapshot()); err != nil {
				fmt.Fprintln(os.Stderr, "events:", err)
			}
		}
	}
}
