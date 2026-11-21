package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/joho/godotenv"
)

const refreshLead = 30 * time.Second
const checkInterval = 2 * time.Minute

const defaultLogRetentionDays = 1
const defaultMaxLogSize = 5 * 1024 * 1024 // 5 MB

type tokenPayload struct {
	Exp int64 `json:"exp"`
	Iat int64 `json:"iat"`
	V   int   `json:"v"`
}

// ---------------------------------------------------------------------------
// Logging: rotating, size-capped, disk-friendly for small-volume hosts
// ---------------------------------------------------------------------------

// rotatingLogWriter writes to a dated file (bot-YYYY-MM-DD.log), rotates at
// midnight and whenever a file exceeds maxSize, and deletes files older than
// `days`. Designed to stay within a few MB on disk even under error loops.
type rotatingLogWriter struct {
	dir     string
	days    int
	maxSize int64
	mu      sync.Mutex
	file    *os.File
	curDate string
	curSize int64
}

func newRotatingLogWriter(dir string, days int, maxSize int64) (*rotatingLogWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if days <= 0 {
		days = defaultLogRetentionDays
	}
	if maxSize <= 0 {
		maxSize = defaultMaxLogSize
	}
	w := &rotatingLogWriter{
		dir:     dir,
		days:    days,
		maxSize: maxSize,
	}
	w.cleanupOld()
	return w, nil
}

func (w *rotatingLogWriter) openFile(name string) error {
	if w.file != nil {
		_ = w.file.Close()
	}
	path := filepath.Join(w.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.file = f
	w.curSize = info.Size()
	return nil
}

func (w *rotatingLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	today := time.Now().Format("2006-01-02")

	// Rotate to a fresh daily file if we don't have one for today yet.
	if w.file == nil || w.curDate != today {
		w.curDate = today
		if err := w.openFile(fmt.Sprintf("bot-%s.log", today)); err != nil {
			return 0, err
		}
		w.cleanupOld()
	}

	// If this write would push us over the cap, rotate to a suffixed file.
	if w.curSize+int64(len(p)) > w.maxSize {
		suffix := time.Now().Format("150405")
		if err := w.openFile(fmt.Sprintf("bot-%s.%s.log", today, suffix)); err != nil {
			return 0, err
		}
		// Cleanup on size-rotation too, in case we've been spamming today.
		w.cleanupOld()
	}

	n, err := w.file.Write(p)
	w.curSize += int64(n)
	return n, err
}

func (w *rotatingLogWriter) cleanupOld() {
	cutoff := time.Now().AddDate(0, 0, -w.days)
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), "bot-") || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(w.dir, e.Name()))
		}
	}
}

func (w *rotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// setupLogging wires up log output based on env vars:
//   LOG_TO_FILE        - "true" to enable file logging (default: true)
//   LOG_DIR            - directory for log files (default: "logs")
//   LOG_RETENTION_DAYS - files older than this are deleted (default: 1)
//   LOG_MAX_SIZE_MB    - per-file size cap in MB (default: 5)
func setupLogging() (*rotatingLogWriter, error) {
	if strings.EqualFold(os.Getenv("LOG_TO_FILE"), "false") {
		log.Printf("File logging disabled via LOG_TO_FILE=false")
		return nil, nil
	}

	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "logs"
	}

	days, _ := strconv.Atoi(os.Getenv("LOG_RETENTION_DAYS"))
	if days <= 0 {
		days = defaultLogRetentionDays
	}

	sizeMB, _ := strconv.Atoi(os.Getenv("LOG_MAX_SIZE_MB"))
	if sizeMB <= 0 {
		sizeMB = int(defaultMaxLogSize / (1024 * 1024))
	}
	maxSize := int64(sizeMB) * 1024 * 1024

	w, err := newRotatingLogWriter(logDir, days, maxSize)
	if err != nil {
		return nil, err
	}
	log.SetOutput(io.MultiWriter(os.Stdout, w))
	log.Printf("File logging enabled (dir=%q, retention=%dd, maxSize=%dMB)",
		logDir, days, sizeMB)
	return w, nil
}

// ---------------------------------------------------------------------------
// Token / crypto helpers (unchanged logic)
// ---------------------------------------------------------------------------

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	var data []byte
	if envPem := os.Getenv("INTERMEDIATE_PRIVATE_PEM"); envPem != "" {
		data = []byte(envPem)
	} else {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key data")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	key, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want ed25519.PrivateKey", keyAny)
	}
	return key, nil
}

// makeToken now takes the pre-computed Base64 strings to save CPU
func makeToken(priv ed25519.PrivateKey, intPubB64 string, certB64 string, period time.Duration) (string, int64) {
	now := time.Now().Unix()
	exp := now + int64(period.Seconds())

	p := tokenPayload{Exp: exp, Iat: now, V: 1}
	pb, _ := json.Marshal(p)

	// Sign the payload with the Intermediate Private Key
	sig := ed25519.Sign(priv, pb)

	return base64.RawURLEncoding.EncodeToString(pb) + "." +
		base64.RawURLEncoding.EncodeToString(sig) + "." +
		intPubB64 + "." +
		certB64, exp
}

func renderMessage(token string, exp int64) string {
	return fmt.Sprintf(
		"🔑 **Current key** (paste into the external):\n```\n%s\n```\n⏳ Expires <t:%d:R> — copy again before it does.",
		token, exp,
	)
}

func findExistingMessage(s *discordgo.Session, channelID, botID string) string {
	msgs, err := s.ChannelMessages(channelID, 20, "", "", "")
	if err != nil {
		log.Printf("history fetch: %v", err)
		return ""
	}
	for _, m := range msgs {
		if m.Author != nil && m.Author.ID == botID && strings.Contains(m.Content, "Current key") {
			return m.ID
		}
	}
	return ""
}

func isUnknownMessage(err error) bool {
	var restErr *discordgo.RESTError
	if errors.As(err, &restErr) && restErr.Message != nil {
		return restErr.Message.Code == discordgo.ErrCodeUnknownMessage
	}
	return false
}

func printRootPublicKeyInfo(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("⚠️ Warning: could not read root public key at %s", path)
		log.Printf("   (This is fine, the bot will still work. Just make sure your client has it.)")
		return
	}
	fp := sha256.Sum256(data)
	log.Printf("Root Public Key SHA-256: %x", fp)
	fmt.Printf("\n--- ROOT PUBLIC KEY (paste into client/embedded_public_key.h) ---\n%s--- end ---\n\n", string(data))
}

func updateOrRecreate(dg *discordgo.Session, channelID string, messageID *string, tok string, exp int64) {
	content := renderMessage(tok, exp)

	if *messageID != "" {
		_, err := dg.ChannelMessageEdit(channelID, *messageID, content)
		if err == nil {
			return
		}
		if isUnknownMessage(err) {
			log.Printf("Token message was deleted — recreating")
			*messageID = ""
		} else {
			log.Printf("edit error: %v", err)
			return
		}
	}

	msg, err := dg.ChannelMessageSend(channelID, content)
	if err != nil {
		log.Printf("send error: %v", err)
	} else {
		*messageID = msg.ID
		log.Printf("Created new message %s", *messageID)
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	// Logging is set up FIRST so nothing is lost before it's ready.
	logWriter, err := setupLogging()
	if err != nil {
		log.Printf("⚠️ Could not set up file logging: %v (continuing with stdout only)", err)
	} else if logWriter != nil {
		defer logWriter.Close()
	}

	if err := godotenv.Load(); err != nil {
		log.Printf("no .env loaded: %v", err)
	}

	token := os.Getenv("DISCORD_TOKEN")
	channelID := os.Getenv("CHANNEL_ID")

	// File Paths
	intPrivPath := os.Getenv("INTERMEDIATE_PRIVATE_PATH")
	if intPrivPath == "" {
		intPrivPath = "intermediate_private.pem"
	}
	certPath := os.Getenv("CERT_PATH")
	if certPath == "" {
		certPath = "intermediate_cert.bin"
	}
	rootPubPath := os.Getenv("ROOT_PUBLIC_PATH")
	if rootPubPath == "" {
		rootPubPath = "root_public.pem"
	}

	periodSec, _ := strconv.Atoi(os.Getenv("PERIOD_SEC"))
	if periodSec == 0 {
		periodSec = 1800
	}
	period := time.Duration(periodSec) * time.Second

	if token == "" || channelID == "" {
		log.Fatal("DISCORD_TOKEN and CHANNEL_ID must be set in .env")
	}

	// 1. Load Intermediate Private Key
	priv, err := loadPrivateKey(intPrivPath)
	if err != nil {
		log.Fatalf("load intermediate private key: %v", err)
	}

	// 2. Load Certificate
	cert, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("load certificate: %v", err)
	}
	if len(cert) != ed25519.SignatureSize {
		log.Fatalf("invalid certificate: expected %d bytes, got %d", ed25519.SignatureSize, len(cert))
	}

	// 3. Pre-compute Base64 strings to optimize token generation
	rawPub := priv.Public().(ed25519.PublicKey)
	intPubB64 := base64.RawURLEncoding.EncodeToString(rawPub)
	certB64 := base64.RawURLEncoding.EncodeToString(cert)

	// 4. Print Root Key Info for the C++ Client
	printRootPublicKeyInfo(rootPubPath)

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Fatalf("new session: %v", err)
	}

	me, err := dg.User("@me")
	if err != nil {
		log.Fatalf("fetch bot user: %v", err)
	}
	log.Printf("Logged in as %s#%s (%s)", me.Username, me.Discriminator, me.ID)
	log.Printf("Rotating every %s, checking existence every %s", period, checkInterval)

	messageID := findExistingMessage(dg, channelID, me.ID)
	if messageID != "" {
		log.Printf("Reusing message %s", messageID)
	}

	tok, exp := makeToken(priv, intPubB64, certB64, period)
	updateOrRecreate(dg, channelID, &messageID, tok, exp)
	log.Printf("Posted initial token, expires %s", time.Unix(exp, 0).UTC().Format(time.RFC3339))

	nextRotation := time.Unix(exp, 0).Add(-refreshLead)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		timeUntilRotation := time.Until(nextRotation)

		sleepFor := checkInterval
		if timeUntilRotation > 0 && timeUntilRotation < sleepFor {
			sleepFor = timeUntilRotation
		}
		if sleepFor < time.Second {
			sleepFor = time.Second
		}

		select {
		case <-time.After(sleepFor):
		case <-stop:
			log.Println("shutting down")
			return
		}

		if time.Now().After(nextRotation) {
			// It's time to rotate!
			tok, exp = makeToken(priv, intPubB64, certB64, period)
			updateOrRecreate(dg, channelID, &messageID, tok, exp)
			log.Printf("Rotated token, expires %s", time.Unix(exp, 0).UTC().Format(time.RFC3339))
			nextRotation = time.Unix(exp, 0).Add(-refreshLead)
		} else {
			// We woke up for a heartbeat check
			_, err := dg.ChannelMessage(channelID, messageID)
			if err != nil && isUnknownMessage(err) {
				log.Printf("Message missing during heartbeat check — recreating")
				messageID = ""
				updateOrRecreate(dg, channelID, &messageID, tok, exp)
			}
		}
	}
}