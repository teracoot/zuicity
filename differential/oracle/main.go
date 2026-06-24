// Command dialer-link-oracle is a differential-testing oracle for the Juicity
// Rust port. It reads one input per line on stdin, parses it with the exact
// upstream surface, and emits one normalized JSON result per line on stdout.
//
// Two modes are selected by argv[1]:
//
//	dialer (default) - parse each line as a dialer_link via the upstream
//	                   daeuniverse dialer that juicity registers. Result:
//	                     {"ok":true,"protocol":"socks5","host":"127.0.0.1","port":1080}
//	                     {"ok":false}
//	config           - decode each line as a Juicity config JSON exactly as
//	                   upstream config.ReadConfig does (encoding/json into the
//	                   upstream Config struct). Result:
//	                     {"ok":true}
//	                     {"ok":false}
//
// Inputs are base64-encoded (StdEncoding) when decodable, else used verbatim.
// Parsing is pure (no network I/O), so the oracle is safe against arbitrary
// fuzzer-generated input.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"

	// Register exactly the dialer schemes juicity's cmd/server/server.go imports.
	_ "github.com/daeuniverse/outbound/dialer/http"
	_ "github.com/daeuniverse/outbound/dialer/hysteria2"
	_ "github.com/daeuniverse/outbound/dialer/juicity"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocksr"
	_ "github.com/daeuniverse/outbound/dialer/socks"
	_ "github.com/daeuniverse/outbound/dialer/trojan"
	_ "github.com/daeuniverse/outbound/dialer/tuic"
	_ "github.com/daeuniverse/outbound/dialer/v2ray"
)

type result struct {
	OK       bool   `json:"ok"`
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// upstreamConfig mirrors the upstream juicity config.Config struct so that
// encoding/json decoding behaves identically to upstream config.ReadConfig.
type upstreamConfig struct {
	Server                string            `json:"server"`
	Uuid                  string            `json:"uuid"`
	Password              string            `json:"password"`
	Sni                   string            `json:"sni"`
	AllowInsecure         bool              `json:"allow_insecure"`
	PinnedCertChainSha256 string            `json:"pinned_certchain_sha256"`
	ProtectPath           string            `json:"protect_path"`
	Forward               map[string]string `json:"forward"`
	Users                 map[string]string `json:"users"`
	Certificate           string            `json:"certificate"`
	PrivateKey            string            `json:"private_key"`
	Fwmark                string            `json:"fwmark"`
	SendThrough           string            `json:"send_through"`
	DialerLink            string            `json:"dialer_link"`
	DisableOutboundUdp443 bool              `json:"disable_outbound_udp443"`
	Listen                string            `json:"listen"`
	CongestionControl     string            `json:"congestion_control"`
	LogLevel              string            `json:"log_level"`
}

func parseDialer(link string) result {
	var d netproxy.Dialer = direct.SymmetricDirect
	d, property, err := dialer.NewNetproxyDialerFromLink(d, &dialer.ExtraOption{}, link)
	if err != nil || d == nil || property == nil {
		return result{OK: false}
	}
	host, portStr, splitErr := net.SplitHostPort(property.Address)
	if splitErr != nil {
		return result{OK: true, Protocol: property.Protocol}
	}
	port, _ := strconv.Atoi(portStr)
	return result{OK: true, Protocol: property.Protocol, Host: host, Port: port}
}

func parseConfig(raw string) result {
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	var c upstreamConfig
	if err := decoder.Decode(&c); err != nil {
		return result{OK: false}
	}
	return result{OK: true}
}

func decodeInput(line string) string {
	decoded, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return line
	}
	return string(decoded)
}

func main() {
	mode := "dialer"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		input := decodeInput(line)
		var res result
		switch mode {
		case "config":
			res = parseConfig(input)
		default:
			res = parseDialer(input)
		}
		encoded, _ := json.Marshal(res)
		writer.Write(encoded)
		writer.WriteByte('\n')
	}
}
