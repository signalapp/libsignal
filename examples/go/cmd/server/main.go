package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	transport "signalexample/transport"
)

type protocolAddress struct {
	Name     string `json:"name"`
	DeviceID uint32 `json:"device_id"`
}

type queuedMessage struct {
	From       protocolAddress `json:"from"`
	CipherType uint8           `json:"cipher_type"`
	Payload    []byte          `json:"payload"`
	Timestamp  int64           `json:"timestamp"`
}

type sendRequest struct {
	From       protocolAddress `json:"from"`
	To         protocolAddress `json:"to"`
	CipherType uint8           `json:"cipher_type"`
	Payload    []byte          `json:"payload"`
}

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

type user struct {
	Password string
	Bundles  map[uint32]*transport.BundlePayload
	Queues   map[uint32][]queuedMessage
}

type session struct {
	Name     string
	DeviceID uint32
	Expires  time.Time
}

type memoryStore struct {
	mu       sync.RWMutex
	users    map[string]*user
	sessions map[string]session
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		users:    make(map[string]*user),
		sessions: make(map[string]session),
	}
}

func (s *memoryStore) createUser(name, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[name]; exists {
		return fmt.Errorf("user %s already exists", name)
	}
	s.users[name] = &user{
		Password: password,
		Bundles:  make(map[uint32]*transport.BundlePayload),
		Queues:   make(map[uint32][]queuedMessage),
	}
	return nil
}

func (s *memoryStore) verifyUser(name, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[name]
	if !ok {
		return false
	}
	return u.Password == password
}

func (s *memoryStore) putBundle(name string, deviceID uint32, payload *transport.BundlePayload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return fmt.Errorf("unknown user %s", name)
	}
	copy := *payload
	u.Bundles[deviceID] = &copy
	return nil
}

func (s *memoryStore) getBundle(name string, deviceID uint32) (*transport.BundlePayload, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[name]
	if !ok {
		return nil, false
	}
	payload, ok := u.Bundles[deviceID]
	if !ok {
		return nil, false
	}
	copy := *payload
	return &copy, true
}

func (s *memoryStore) enqueue(name string, deviceID uint32, message queuedMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return fmt.Errorf("unknown user %s", name)
	}
	// Copy payload to avoid sharing slices across goroutines.
	cloned := message
	cloned.Payload = append([]byte(nil), message.Payload...)
	u.Queues[deviceID] = append(u.Queues[deviceID], cloned)
	return nil
}

func (s *memoryStore) drain(name string, deviceID uint32) ([]queuedMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return nil, fmt.Errorf("unknown user %s", name)
	}
	messages := u.Queues[deviceID]
	delete(u.Queues, deviceID)
	return messages, nil
}

func (s *memoryStore) newSession(name string, deviceID uint32, ttl time.Duration) (string, session, error) {
	token, err := generateToken()
	if err != nil {
		return "", session{}, err
	}
	sess := session{
		Name:     name,
		DeviceID: deviceID,
		Expires:  time.Now().Add(ttl),
	}
	s.mu.Lock()
	s.sessions[token] = sess
	s.mu.Unlock()
	return token, sess, nil
}

func (s *memoryStore) getSession(token string) (session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[token]
	if !ok {
		return session{}, false
	}
	if time.Now().After(sess.Expires) {
		return session{}, false
	}
	return sess, true
}

func generateToken() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	flag.Parse()

	store := newMemoryStore()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		handleRegister(store, w, r)
	})
	mux.HandleFunc("/v1/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		handleLogin(store, w, r)
	})
	mux.HandleFunc("/v1/devices/", func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireSession(store, w, r)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodPost:
			handleSetBundle(store, sess, w, r)
		case http.MethodGet:
			handleGetBundle(store, w, r)
		default:
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
	mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		sess, ok := requireSession(store, w, r)
		if !ok {
			return
		}
		handleEnqueueMessage(store, sess, w, r)
	})
	mux.HandleFunc("/v1/messages/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		sess, ok := requireSession(store, w, r)
		if !ok {
			return
		}
		handleDrainMessages(store, sess, w, r)
	})

	server := &http.Server{
		Addr:    *listen,
		Handler: requestLogger(mux),
	}

	log.Printf("Signal demo server listening on %s", *listen)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server stopped: %v", err)
	}
}

func handleRegister(store *memoryStore, w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if req.Name == "" || req.Password == "" {
		httpError(w, http.StatusBadRequest, "name and password are required")
		return
	}
	if err := store.createUser(req.Name, req.Password); err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
}

func handleLogin(store *memoryStore, w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if !store.verifyUser(req.Name, req.Password) {
		httpError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, sess, err := store.newSession(req.Name, req.DeviceID, 12*time.Hour)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("login user=%s device=%d token=%s expires=%s", sess.Name, sess.DeviceID, token, sess.Expires.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, loginResponse{Token: token})
}

func handleSetBundle(store *memoryStore, sess session, w http.ResponseWriter, r *http.Request) {
	name, deviceID, err := parseDevicePath(r.URL.Path)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if name != sess.Name || deviceID != sess.DeviceID {
		httpError(w, http.StatusForbidden, "cannot upload bundle for another device")
		return
	}

	var payload transport.BundlePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if payload.RegistrationID == 0 {
		httpError(w, http.StatusBadRequest, "registration_id is required")
		return
	}
	payload.DeviceID = deviceID

	if err := store.putBundle(name, deviceID, &payload); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stored"})
}

func handleGetBundle(store *memoryStore, w http.ResponseWriter, r *http.Request) {
	name, deviceID, err := parseDevicePath(r.URL.Path)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload, ok := store.getBundle(name, deviceID)
	if !ok {
		httpError(w, http.StatusNotFound, "bundle not found")
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func handleEnqueueMessage(store *memoryStore, sess session, w http.ResponseWriter, r *http.Request) {
	var req sendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	fmt.Print(req)
	if req.Payload == nil {
		httpError(w, http.StatusBadRequest, "payload is required")
		return
	}
	if req.From.Name != sess.Name || req.From.DeviceID != sess.DeviceID {
		httpError(w, http.StatusForbidden, "session does not match sender")
		return
	}
	message := queuedMessage{
		From:       req.From,
		CipherType: req.CipherType,
		Payload:    req.Payload,
		Timestamp:  time.Now().UnixMilli(),
	}
	if err := store.enqueue(req.To.Name, req.To.DeviceID, message); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "queued"})
}

func handleDrainMessages(store *memoryStore, sess session, w http.ResponseWriter, r *http.Request) {
	name, deviceID, err := parseMessagesPath(r.URL.Path)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if name != sess.Name || deviceID != sess.DeviceID {
		httpError(w, http.StatusForbidden, "session does not match inbox")
		return
	}
	messages, err := store.drain(name, deviceID)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, messages)
}

func requireSession(store *memoryStore, w http.ResponseWriter, r *http.Request) (session, bool) {
	token := r.Header.Get("X-Session-Token")
	if token == "" {
		httpError(w, http.StatusUnauthorized, "missing session token")
		return session{}, false
	}
	sess, ok := store.getSession(token)
	if !ok {
		httpError(w, http.StatusUnauthorized, "invalid session token")
		return session{}, false
	}
	return sess, true
}

func parseDevicePath(path string) (string, uint32, error) {
	suffix := strings.TrimPrefix(path, "/v1/devices/")
	parts := strings.Split(suffix, "/")
	if len(parts) != 3 || parts[2] != "bundle" {
		return "", 0, fmt.Errorf("expected /v1/devices/{name}/{device}/bundle, got %s", path)
	}
	deviceID, err := parseDeviceID(parts[1])
	if err != nil {
		return "", 0, err
	}
	return parts[0], deviceID, nil
}

func parseMessagesPath(path string) (string, uint32, error) {
	suffix := strings.TrimPrefix(path, "/v1/messages/")
	parts := strings.Split(suffix, "/")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("expected /v1/messages/{name}/{device}, got %s", path)
	}
	deviceID, err := parseDeviceID(parts[1])
	if err != nil {
		return "", 0, err
	}
	return parts[0], deviceID, nil
}

func parseDeviceID(raw string) (uint32, error) {
	if raw == "" {
		return 0, errors.New("device id is required")
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid device id: %w", err)
	}
	return uint32(value), nil
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		var bodyCopy []byte
		if r.Body != nil {
			var err error
			bodyCopy, err = io.ReadAll(r.Body)
			if err != nil {
				log.Printf("failed to read request body: %v", err)
			}
			if err := r.Body.Close(); err != nil {
				log.Printf("failed to close request body: %v", err)
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyCopy))
		}

		if len(bodyCopy) > 0 {
			// log.Printf("%s %s body=%s", r.Method, r.URL.Path, string(bodyCopy))
		} else {
			log.Printf("%s %s body=<empty>", r.Method, r.URL.Path)
		}
		next.ServeHTTP(w, r)
		duration := time.Since(start).Truncate(time.Millisecond)
		log.Printf("%s %s %s", r.Method, r.URL.Path, duration)
	})
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("write JSON failed: %v", err)
	}
}
