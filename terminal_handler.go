package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// ============================================================
// Port Scanner
// ============================================================

// PortScanResult holds the result of scanning common management ports
type PortScanResult struct {
	SSH    bool `json:"ssh"`
	Telnet bool `json:"telnet"`
	HTTP   bool `json:"http"`
	HTTPS  bool `json:"https"`
	// Actual open ports for detail
	SSHPort    int `json:"ssh_port"`
	TelnetPort int `json:"telnet_port"`
	HTTPPort   int `json:"http_port"`
	HTTPSPort  int `json:"https_port"`
}

// checkPort tests if a TCP port is open with a 2-second timeout
func checkPort(ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// scanPorts probes SSH, Telnet, HTTP, HTTPS ports concurrently
func scanPorts(ip string) PortScanResult {
	result := PortScanResult{
		SSHPort:    22,
		TelnetPort: 23,
		HTTPPort:   80,
		HTTPSPort:  443,
	}

	var wg sync.WaitGroup
	wg.Add(4)

	go func() { defer wg.Done(); result.SSH = checkPort(ip, 22) }()
	go func() { defer wg.Done(); result.Telnet = checkPort(ip, 23) }()
	go func() { defer wg.Done(); result.HTTP = checkPort(ip, 80) }()
	go func() { defer wg.Done(); result.HTTPS = checkPort(ip, 443) }()

	wg.Wait()
	return result
}

// checkPortsHandler handles GET /api/check-ports?id=172.20.254.10
func checkPortsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ip := r.URL.Query().Get("id")
	if ip == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing 'id' parameter"})
		return
	}

	result := scanPorts(ip)
	json.NewEncoder(w).Encode(result)
}

// ============================================================
// WebSocket Terminal Proxy
// ============================================================

// upgrader opens the terminal's WebSocket for this server's own pages only:
// a page of another site could otherwise use the login cookie
var upgrader = websocket.Upgrader{
	CheckOrigin:     authFromHere,
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

// terminalHandler handles WebSocket /api/terminal
// Query params: id, proto (ssh/telnet), port, user, pass, cols, rows
func terminalHandler(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("id")
	proto := r.URL.Query().Get("proto")
	portStr := r.URL.Query().Get("port")
	user := r.URL.Query().Get("user")
	pass := r.URL.Query().Get("pass")
	colsStr := r.URL.Query().Get("cols")
	rowsStr := r.URL.Query().Get("rows")

	if ip == "" || proto == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	port := 22
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	cols := 120
	rows := 30
	if colsStr != "" {
		if c, err := strconv.Atoi(colsStr); err == nil && c > 0 {
			cols = c
		}
	}
	if rowsStr != "" {
		if rr, err := strconv.Atoi(rowsStr); err == nil && rr > 0 {
			rows = rr
		}
	}

	// Upgrade to WebSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[Terminal] WebSocket upgrade failed: %v", err)
		return
	}
	defer ws.Close()

	switch proto {
	case "ssh":
		handleSSHSession(ws, ip, port, user, pass, cols, rows)
	case "telnet":
		handleTelnetSession(ws, ip, port)
	default:
		ws.WriteMessage(websocket.TextMessage, []byte("Unknown protocol: "+proto))
	}
}

// ============================================================
// SSH Session Handler
// ============================================================

func handleSSHSession(ws *websocket.Conn, ip string, port int, user, pass string, cols, rows int) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	// SSH client config
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pass
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Connect
	ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[33mConnecting to %s via SSH...\033[0m\r\n", addr)))

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[31mSSH connection failed: %v\033[0m\r\n", err)))
		return
	}
	defer client.Close()

	// Open session
	session, err := client.NewSession()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[31mSession failed: %v\033[0m\r\n", err)))
		return
	}
	defer session.Close()

	// Request PTY
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[31mPTY request failed: %v\033[0m\r\n", err)))
		return
	}

	// Get stdin/stdout pipes
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[31mStdin pipe failed: %v\033[0m\r\n", err)))
		return
	}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[31mStdout pipe failed: %v\033[0m\r\n", err)))
		return
	}

	stderrPipe, err := session.StderrPipe()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[31mStderr pipe failed: %v\033[0m\r\n", err)))
		return
	}

	// Start shell
	if err := session.Shell(); err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[31mShell failed: %v\033[0m\r\n", err)))
		return
	}

	ws.WriteMessage(websocket.TextMessage, []byte("\033[32mConnected!\033[0m\r\n"))

	done := make(chan struct{})

	// SSH stdout → WebSocket
	go func() {
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()
		buf := make([]byte, 4096)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				if wErr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); wErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// SSH stderr → WebSocket
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				ws.WriteMessage(websocket.BinaryMessage, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket → SSH stdin
	go func() {
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if _, err := stdinPipe.Write(msg); err != nil {
				return
			}
		}
	}()

	// Wait for session to end
	session.Wait()
	select {
	case <-done:
	default:
		close(done)
	}
	ws.WriteMessage(websocket.TextMessage, []byte("\r\n\033[33mSession closed.\033[0m\r\n"))
}

// ============================================================
// Telnet Session Handler
// ============================================================

func handleTelnetSession(ws *websocket.Conn, ip string, port int) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[33mConnecting to %s via Telnet...\033[0m\r\n", addr)))

	// Raw TCP connection for Telnet
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[31mTelnet connection failed: %v\033[0m\r\n", err)))
		return
	}
	defer conn.Close()

	ws.WriteMessage(websocket.TextMessage, []byte("\033[32mConnected!\033[0m\r\n"))

	done := make(chan struct{})

	// Telnet → WebSocket
	go func() {
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				// Filter Telnet IAC commands (0xFF prefix)
				filtered := filterTelnetIAC(buf[:n], conn)
				if len(filtered) > 0 {
					if wErr := ws.WriteMessage(websocket.BinaryMessage, filtered); wErr != nil {
						return
					}
				}
			}
			if err != nil {
				if err != io.EOF {
					ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\n\033[31mConnection lost: %v\033[0m\r\n", err)))
				}
				return
			}
		}
	}()

	// WebSocket → Telnet
	go func() {
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if _, err := conn.Write(msg); err != nil {
				return
			}
		}
	}()

	<-done
	ws.WriteMessage(websocket.TextMessage, []byte("\r\n\033[33mTelnet session closed.\033[0m\r\n"))
}

// filterTelnetIAC handles basic Telnet IAC negotiation
// Strips IAC sequences from data and auto-responds to DO/WILL/WONT/DONT
func filterTelnetIAC(data []byte, conn net.Conn) []byte {
	var clean []byte
	i := 0
	for i < len(data) {
		if data[i] == 0xFF && i+2 < len(data) {
			cmd := data[i+1]
			opt := data[i+2]

			switch cmd {
			case 0xFB: // WILL → respond DONT
				conn.Write([]byte{0xFF, 0xFE, opt})
			case 0xFD: // DO → respond WONT
				conn.Write([]byte{0xFF, 0xFC, opt})
			case 0xFC: // WONT → ignore
			case 0xFE: // DONT → ignore
			}
			i += 3
		} else if data[i] == 0xFF && i+1 < len(data) && data[i+1] == 0xFF {
			// Escaped 0xFF
			clean = append(clean, 0xFF)
			i += 2
		} else {
			clean = append(clean, data[i])
			i++
		}
	}
	return clean
}

// registerTerminalRoutes registers terminal-related HTTP handlers
func registerTerminalRoutes() {
	http.HandleFunc("/api/check-ports", checkPortsHandler)
	http.HandleFunc("/api/terminal", terminalHandler)
}
