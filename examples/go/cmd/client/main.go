package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"signalexample/ffi"
	"signalexample/transport"
)

const registrationID = 2024

type registerRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type loginRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	DeviceID uint32 `json:"device_id"`
}

type loginResponse struct {
	Token string `json:"token"`
}

type protocolAddressJSON struct {
	Name     string `json:"name"`
	DeviceID uint32 `json:"device_id"`
}

type sendRequest struct {
	From       protocolAddressJSON `json:"from"`
	To         protocolAddressJSON `json:"to"`
	CipherType uint8               `json:"cipher_type"`
	Payload    []byte              `json:"payload"`
}

type queuedMessage struct {
	From       protocolAddressJSON `json:"from"`
	CipherType uint8               `json:"cipher_type"`
	Payload    []byte              `json:"payload"`
	Timestamp  int64               `json:"timestamp"`
}

type sessionState struct {
	token       string
	username    string
	deviceID    uint32
	client      *ffi.Client
	selfAddr    ffi.Address
	peerAddrs   map[string]ffi.Address
	peerReady   map[string]bool
	peerDevices map[string]map[uint32]struct{}
	httpClient  *http.Client
	serverURL   string
}

func main() {
	serverFlag := flag.String("server", "http://localhost:8080", "demo server base URL")
	flag.Parse()

	httpClient := &http.Client{Timeout: 10 * time.Second}
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("Select an option:")
		fmt.Println("1) register")
		fmt.Println("2) login")
		fmt.Println("3) exit")
		choice := strings.TrimSpace(readLine(reader, "> "))
		switch choice {
		case "1", "register":
			handleRegister(reader, httpClient, *serverFlag)
		case "2", "login":
			if err := handleLogin(reader, httpClient, *serverFlag); err != nil {
				log.Printf("login error: %v", err)
			}
		case "3", "exit", "quit":
			fmt.Println("Goodbye")
			return
		default:
			fmt.Println("Unknown choice. Please enter 1, 2, or 3.")
		}
	}
}

func handleRegister(reader *bufio.Reader, httpClient *http.Client, server string) {
	name := strings.TrimSpace(readLine(reader, "Choose a username: "))
	password := strings.TrimSpace(readLine(reader, "Choose a password: "))
	if name == "" || password == "" {
		fmt.Println("Username and password must not be empty.")
		return
	}
	req := registerRequest{Name: name, Password: password}
	if err := postJSON(httpClient, fmt.Sprintf("%s/v1/register", server), req, ""); err != nil {
		fmt.Printf("Registration failed: %v\n", err)
		return
	}
	fmt.Printf("Registered user %s. You can now log in.\n", name)
}

func handleLogin(reader *bufio.Reader, httpClient *http.Client, server string) error {
	name := strings.TrimSpace(readLine(reader, "Username: "))
	password := strings.TrimSpace(readLine(reader, "Password: "))
	deviceID, err := promptDeviceID(reader)
	if err != nil {
		return err
	}

	var loginResp loginResponse
	if err := postAndDecode(httpClient, fmt.Sprintf("%s/v1/login", server), loginRequest{
		Name:     name,
		Password: password,
		DeviceID: deviceID,
	}, "", &loginResp); err != nil {
		return err
	}
	if loginResp.Token == "" {
		return fmt.Errorf("server returned empty token")
	}
	fmt.Printf("Logged in as %s (device %d).\n", name, deviceID)

	client, err := ffi.NewClient(name, registrationID, deviceID)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	selfAddr, err := ffi.NewAddress(name, deviceID)
	if err != nil {
		client.Close()
		return fmt.Errorf("create address: %w", err)
	}

	state := &sessionState{
		token:       loginResp.Token,
		username:    name,
		deviceID:    deviceID,
		client:      client,
		selfAddr:    selfAddr,
		peerAddrs:   make(map[string]ffi.Address),
		peerReady:   make(map[string]bool),
		peerDevices: make(map[string]map[uint32]struct{}),
		httpClient:  httpClient,
		serverURL:   server,
	}

	if err := publishBundle(state); err != nil {
		cleanupSession(state)
		return fmt.Errorf("upload bundle: %w", err)
	}

	sessionLoop(reader, state)
	cleanupSession(state)
	return nil
}

func sessionLoop(reader *bufio.Reader, state *sessionState) {
	fmt.Println("Available commands: send <user> <device> <message>, sendall <user> <message>, refresh, logout")
	for {
		line := strings.TrimSpace(readLine(reader, "session> "))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		switch strings.ToLower(fields[0]) {
		case "send":
			parts := strings.SplitN(line, " ", 4)
			if len(parts) < 4 {
				fmt.Println("Usage: send <user> <device> <message>")
				continue
			}
			peer := strings.TrimSpace(parts[1])
			deviceID, err := parseDeviceIDString(strings.TrimSpace(parts[2]))
			if err != nil {
				fmt.Printf("invalid device id: %v\n", err)
				continue
			}
			message := strings.TrimSpace(parts[3])
			if message == "" {
				fmt.Println("Message must not be empty.")
				continue
			}
			if err := sendMessage(state, peer, deviceID, []byte(message)); err != nil {
				fmt.Printf("send failed: %v\n", err)
			}
		case "sendall":
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 3 {
				fmt.Println("Usage: sendall <user> <message>")
				continue
			}
			peer := strings.TrimSpace(parts[1])
			message := strings.TrimSpace(parts[2])
			if message == "" {
				fmt.Println("Message must not be empty.")
				continue
			}
			devices := state.peerDevices[peer]
			if len(devices) == 0 {
				fmt.Println("No known devices for that user. Try refresh or send with a specific device first.")
				continue
			}
			for deviceID := range devices {
				if err := sendMessage(state, peer, deviceID, []byte(message)); err != nil {
					fmt.Printf("send to %s/%d failed: %v\n", peer, deviceID, err)
				}
			}
		case "refresh":
			if err := refreshInbox(state); err != nil {
				fmt.Printf("refresh failed: %v\n", err)
			}
		case "logout":
			fmt.Println("Logged out.")
			return
		default:
			fmt.Println("Unknown command. Try: send <user> <device> <message>, sendall <user> <message>, refresh, logout")
		}
	}
}

func publishBundle(state *sessionState) error {
	bundle, err := state.client.GeneratePreKeyBundle(registrationID, state.deviceID, 1, 1, 1)
	if err != nil {
		return err
	}
	defer ffi.FreePreKeyBundle(bundle)

	payload, err := ffi.BundleToPayload(bundle)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/v1/devices/%s/%d/bundle", state.serverURL, state.username, state.deviceID)
	return postJSON(state.httpClient, url, payload, state.token)
}

func sendMessage(state *sessionState, peer string, peerDevice uint32, plaintext []byte) error {
	addPeerDevice(state, peer, peerDevice)
	if err := ensurePeerReady(state, peer, peerDevice); err != nil {
		return err
	}
	key := peerKey(peer, peerDevice)
	peerAddr := state.peerAddrs[key]
	msg, err := state.client.Encrypt(peerAddr, plaintext)
	if err != nil {
		return err
	}
	defer ffi.FreeCiphertext(msg)

	req := sendRequest{
		From:       protocolAddressJSON{Name: state.username, DeviceID: state.deviceID},
		To:         protocolAddressJSON{Name: peer, DeviceID: peerDevice},
		CipherType: ffi.CiphertextType(msg),
		Payload:    ffi.CiphertextBytes(msg),
	}
	url := fmt.Sprintf("%s/v1/messages", state.serverURL)
	if err := postJSON(state.httpClient, url, req, state.token); err != nil {
		return err
	}
	fmt.Printf("Sent %d bytes to %s/%d.\n", len(req.Payload), peer, peerDevice)
	return nil
}

func refreshInbox(state *sessionState) error {
	url := fmt.Sprintf("%s/v1/messages/%s/%d", state.serverURL, state.username, state.deviceID)
	var inbox []queuedMessage
	if err := getJSON(state.httpClient, url, state.token, &inbox); err != nil {
		return err
	}
	if len(inbox) == 0 {
		fmt.Println("No new messages.")
		return nil
	}
	for _, msg := range inbox {
		peer := msg.From.Name
		addPeerDevice(state, peer, msg.From.DeviceID)
		if err := ensurePeerReady(state, peer, msg.From.DeviceID); err != nil {
			fmt.Printf("cannot decrypt message from %s: %v\n", peer, err)
			continue
		}
		key := peerKey(peer, msg.From.DeviceID)
		peerAddr := state.peerAddrs[key]
		plaintext, err := decryptMessage(state.client, peerAddr, msg)
		if err != nil {
			fmt.Printf("decrypt failed for %s: %v\n", peer, err)
			continue
		}
		fmt.Printf("[%s/%d] %s\n", peer, msg.From.DeviceID, plaintext)
	}
	return nil
}

func ensurePeerReady(state *sessionState, peer string, peerDevice uint32) error {
	addPeerDevice(state, peer, peerDevice)
	key := peerKey(peer, peerDevice)
	if ready := state.peerReady[key]; ready {
		return nil
	}
	addr, ok := state.peerAddrs[key]
	if !ok {
		var err error
		addr, err = ffi.NewAddress(peer, peerDevice)
		if err != nil {
			return err
		}
		state.peerAddrs[key] = addr
	}

	bundle, err := fetchBundle(state.httpClient, state.serverURL, peer, peerDevice, state.token)
	if err != nil {
		return err
	}
	remoteBundle, err := ffi.BundleFromPayload(bundle)
	if err != nil {
		return err
	}
	defer ffi.FreePreKeyBundle(remoteBundle)

	if err := state.client.ProcessPreKeyBundle(state.peerAddrs[key], remoteBundle); err != nil {
		return err
	}
	state.peerReady[key] = true
	return nil
}

func decryptMessage(client *ffi.Client, peerAddr ffi.Address, msg queuedMessage) (string, error) {
	switch msg.CipherType {
	case ffi.CiphertextTypePreKey:
		pk, err := ffi.PreKeySignalMessageFromBytes(msg.Payload)
		if err != nil {
			return "", err
		}
		defer ffi.FreePreKeySignalMessage(pk)
		plaintext, err := client.DecryptPreKey(peerAddr, pk)
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	case ffi.CiphertextTypeWhisper:
		sig, err := ffi.SignalMessageFromBytes(msg.Payload)
		if err != nil {
			return "", err
		}
		defer ffi.FreeSignalMessage(sig)
		plaintext, err := client.DecryptSignal(peerAddr, sig)
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	default:
		return "", fmt.Errorf("unknown ciphertext type %d", msg.CipherType)
	}
}

func cleanupSession(state *sessionState) {
	for _, addr := range state.peerAddrs {
		ffi.FreeAddress(addr)
	}
	ffi.FreeAddress(state.selfAddr)
	state.client.Close()
}

func readLine(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	line, _ := reader.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func promptDeviceID(reader *bufio.Reader) (uint32, error) {
	for {
		input := strings.TrimSpace(readLine(reader, "Device ID (1-127): "))
		value, err := parseDeviceIDString(input)
		if err != nil {
			fmt.Printf("Invalid device id: %v\n", err)
			continue
		}
		return value, nil
	}
}

func parseDeviceIDString(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, err
	}
	if parsed == 0 || parsed > 127 {
		return 0, fmt.Errorf("out of range")
	}
	return uint32(parsed), nil
}

func addPeerDevice(state *sessionState, peer string, deviceID uint32) {
	devices, ok := state.peerDevices[peer]
	if !ok {
		devices = make(map[uint32]struct{})
		state.peerDevices[peer] = devices
	}
	devices[deviceID] = struct{}{}
}

func peerKey(peer string, deviceID uint32) string {
	return fmt.Sprintf("%s:%d", peer, deviceID)
}

func fetchBundle(httpClient *http.Client, serverURL, name string, deviceID uint32, token string) (*transport.BundlePayload, error) {
	url := fmt.Sprintf("%s/v1/devices/%s/%d/bundle", serverURL, name, deviceID)
	var payload transport.BundlePayload
	if err := getJSON(httpClient, url, token, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func postJSON(client *http.Client, url string, body any, token string) error {
	return postAndDecode(client, url, body, token, nil)
}

func postAndDecode(client *http.Client, url string, body any, token string, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Session-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s status %d: %s", url, resp.StatusCode, bytes.TrimSpace(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func getJSON(client *http.Client, url string, token string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Session-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s status %d: %s", url, resp.StatusCode, bytes.TrimSpace(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
