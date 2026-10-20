// Package bridge forwards ssh-agent protocol messages to the
// termux-ssh-agent-app Android app via `am broadcast`. This intentionally
// uses Termux's own bundled "am" (a lightweight reimplementation, found via
// $PATH) rather than the real /system/bin/am: the real one's "cmd"-style
// low-level Binder call into system_server's ActivityManager is rejected
// outright ("Failed transaction") when run as an ordinary app UID instead of
// shell. Termux's own "am" can deliver the broadcast fine, but cannot wait
// for an ordered broadcast's result on Android 14+, so the actual response
// travels back over a loopback TCP connection that Forward opens a fresh
// listener for per request, telling the app the port via the broadcast. A
// Linux abstract-namespace Unix socket was tried first (the same pattern the
// prior art, tergent + Termux:API, uses) but SELinux denies that connect()
// between two genuinely different app UIDs (confirmed on a real device:
// "Permission denied"); tergent's case works only because Termux and
// Termux:API share a UID via sharedUserId. Loopback TCP is a different
// socket class that Android does not restrict the same way, so it works
// between any two apps that both declare the (automatically granted)
// INTERNET permission.
//
// A single persistent/fixed response port was tried next (simpler to wire
// up) but turned out to be unsound: when a request times out (the app's
// process was killed and had to cold-start, which can take longer than any
// reasonable timeout) the app still finishes the job late and connects to
// the port after Forward has given up — and that stale connection then gets
// handed to Accept() on a *later*, unrelated request, so the response for
// one request gets relayed as the answer to a different one (observed on a
// real device as a broken pipe when writing to an ssh client that had
// already disconnected). A fresh listener per request avoids this by
// construction: a late, stale connection to an already-closed listener is
// simply refused, instead of being silently absorbed by whichever request
// happens to call Accept() next.
//
// Any app on the device can trigger the broadcast (there is no way to check
// the sender's UID for a plain broadcast), so the app seals every response
// to this bridge's own X25519 public key; decryptResponse below undoes that.
// See ../DESIGN.md section 2 for the full story.
package bridge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"
)

const (
	packageName  = "io.github.ge9.termuxsshagent"
	receiver     = packageName + "/.AgentReceiver"
	broadcastAct = packageName + ".SIGN"
	extraData    = "data"
	extraPort    = "port"

	x25519KeySize = 32
	gcmNonceSize  = 12
	// Generous on purpose: if Android has killed the app's process in the
	// background (common; happens well within an hour on stock Android), this
	// broadcast has to cold-start it first, which can take several seconds.
	responseTimeout = 20 * time.Second
)

// LoadPrivateKey reads this bridge's X25519 private key from a PEM file
// (generate one with `openssl genpkey -algorithm X25519`; see README.md).
func LoadPrivateKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdhKey, ok := key.(*ecdh.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an X25519 key", path)
	}
	return ecdhKey, nil
}

// Serve listens on socketPath (use it as SSH_AUTH_SOCK) and answers every
// ssh-agent request on it by calling Forward. It only returns on a fatal
// listener error.
func Serve(socketPath string, privateKey *ecdh.PrivateKey) error {
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go handleConn(conn, privateKey)
	}
}

func handleConn(conn net.Conn, privateKey *ecdh.PrivateKey) {
	defer conn.Close()
	reader := conn
	for {
		message, err := readMessage(reader)
		if err != nil {
			return
		}
		response, err := Forward(message, privateKey)
		if err != nil {
			response = []byte{agentFailure}
		}
		if err := writeMessage(conn, response); err != nil {
			return
		}
	}
}

const agentFailure = 0x05

// readMessage reads one ssh-agent protocol frame: a 4-byte big-endian length
// followed by that many bytes of message body.
func readMessage(r io.Reader) ([]byte, error) {
	var lengthBuf [4]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeMessage(w io.Writer, body []byte) error {
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(body)))
	if _, err := w.Write(lengthBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// Forward sends one ssh-agent message to the app and decrypts its reply. It
// opens a fresh loopback-TCP listener per call, tells the app its port via
// the broadcast, and reads the app's one-shot connection to it; the listener
// is closed as soon as this call is done (success, failure, or timeout), so
// a late/stale connection from a request that already timed out is simply
// refused rather than being picked up by a later request. message and the
// returned response are raw ssh-agent protocol messages with no wire framing
// (callers that speak the framed protocol, like Serve, add/remove it at
// their own transport boundary).
func Forward(message []byte, privateKey *ecdh.PrivateKey) ([]byte, error) {
	listener, port, err := newLoopbackListener()
	if err != nil {
		return nil, fmt.Errorf("listen for response: %w", err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(responseTimeout)); err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(message)
	// Termux's own "am" (not the real /system/bin/am; see the package doc
	// comment) takes the target component as a trailing positional argument
	// rather than -n, and has no --async flag — it just never waits for an
	// ordered broadcast's result on Android 14+, which is fine here since the
	// actual response travels over the loopback listener above instead.
	cmd := exec.Command("am", "broadcast",
		"-a", broadcastAct,
		"--es", extraData, encoded,
		"--ei", extraPort, strconv.Itoa(port),
		receiver,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("am broadcast: %w", err)
	}

	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept response: %w", err)
	}
	defer conn.Close()

	sealed, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return decryptResponse(privateKey, sealed)
}

// newLoopbackListener opens a TCP listener on 127.0.0.1 with a kernel-assigned
// ephemeral port, and returns that port for passing to the app.
func newLoopbackListener() (*net.TCPListener, int, error) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, 0, err
	}
	return listener, listener.Addr().(*net.TCPAddr).Port, nil
}

// decryptResponse undoes the app's sealed-box encryption (ResponseEncryption.kt):
// ephemeral public key (32 bytes) || nonce (12 bytes) || AES-256-GCM ciphertext.
// The key is SHA-256(ephemeral public || our public || ECDH shared secret).
func decryptResponse(privateKey *ecdh.PrivateKey, sealed []byte) ([]byte, error) {
	if len(sealed) < x25519KeySize+gcmNonceSize {
		return nil, fmt.Errorf("sealed response too short")
	}
	ephemeralPublicBytes := sealed[:x25519KeySize]
	nonce := sealed[x25519KeySize : x25519KeySize+gcmNonceSize]
	ciphertext := sealed[x25519KeySize+gcmNonceSize:]

	ephemeralPublic, err := ecdh.X25519().NewPublicKey(ephemeralPublicBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	sharedSecret, err := privateKey.ECDH(ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	hash := sha256.New()
	hash.Write(ephemeralPublicBytes)
	hash.Write(privateKey.PublicKey().Bytes())
	hash.Write(sharedSecret)
	key := hash.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
