package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"

	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// ============================================================================
// SSH Gateway with Username-Based Routing
//
// Instead of mapping port ranges (2200-2300) to VMs, this gateway uses a
// SINGLE port (default: 2222) and routes connections based on the SSH username.
//
// Connection format:  ssh <user_id>@gateway-host -p 2222
//
// The gateway:
//   1. Accepts the SSH TCP connection
//   2. Performs SSH handshake to extract the username (= user_id / openid)
//   3. Looks up the VM's internal IP from Redis (vm:binding:<user_id>)
//   4. Opens a NEW SSH connection to the VM's internal SSH port (port 22)
//   5. Proxies the entire session (shell, PTY, exec, etc.) bidirectionally
//
// Benefits:
//   - Only 1 external port needed (no port-range limitation on VM count)
//   - Simpler firewall rules
//   - Easier for users: they just use their user_id as the SSH username
// ============================================================================

const vmBindingPrefix = "vm:binding:"

// VMBinding mirrors the Redis JSON structure.
// Supports both bridge (camelCase) and orchestrator (snake_case) field names.
type VMBinding struct {
	VMIP        string `json:"vmIp"`
	VMIPAlt     string `json:"vm_ip"`
	SSHPort     int    `json:"sshPort"`
	Status      string `json:"status"`
	ErrorMsg    string `json:"errorMessage,omitempty"`
	SSHPassword string `json:"ssh_password,omitempty"`
}

// GetVMIP returns the VM IP from whichever field is populated.
func (b *VMBinding) GetVMIP() string {
	if b.VMIP != "" {
		return b.VMIP
	}
	return b.VMIPAlt
}

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.Info("Starting SSH Gateway (username-based routing)...")

	listenAddr := getEnv("LISTEN_ADDR", "0.0.0.0:2222")
	redisURL := getEnv("REDIS_URL", "redis://localhost:6379")
	hostKeyPath := getEnv("HOST_KEY_PATH", "/etc/ssh-gateway/host_key")
	vmSSHUser := getEnv("VM_SSH_USER", "user")
	vmSSHPass := getEnv("VM_SSH_PASS", "clawdbot")

	// Connect to Redis
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("Invalid REDIS_URL: %v", err)
	}
	redisClient := redis.NewClient(opt)
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis connection failed: %v", err)
	}
	log.Info("Connected to Redis")

	// Load or generate host key
	hostKey := loadOrGenerateHostKey(hostKeyPath)

	// Build SSH server config
	// We accept ANY password from the client — the username is what matters for routing.
	// The actual VM authentication happens on the second hop.
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			username := conn.User()
			log.WithField("user", username).Debug("Password auth attempt")
			// Accept all passwords at the gateway level.
			// We validate the user_id exists in Redis later.
			return &ssh.Permissions{
				Extensions: map[string]string{
					"user_id": username,
				},
			}, nil
		},
		NoClientAuth: false,
	}
	sshConfig.AddHostKey(hostKey)

	// Start listening
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	log.Infof("SSH Gateway listening on %s", listenAddr)
	log.Info("Connection format: ssh <user_id>@<host> -p <port>")

	// Accept connections
	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					log.WithError(err).Error("Accept error")
					continue
				}
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleSSHConnection(ctx, redisClient, tcpConn, sshConfig, vmSSHUser, vmSSHPass)
			}()
		}
	}()

	// Wait for shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down SSH Gateway...")
	close(done)
	listener.Close()
	wg.Wait()
	redisClient.Close()
	log.Info("SSH Gateway stopped")
}

// handleSSHConnection performs SSH handshake, resolves VM, and proxies the session.
func handleSSHConnection(
	ctx context.Context,
	redisClient *redis.Client,
	tcpConn net.Conn,
	config *ssh.ServerConfig,
	vmUser, vmPass string,
) {
	defer tcpConn.Close()

	// Step 1: SSH handshake with client
	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
	if err != nil {
		log.WithError(err).Debug("SSH handshake failed")
		return
	}
	defer sshConn.Close()

	userID := sshConn.User()
	log.WithFields(log.Fields{
		"user_id": userID,
		"remote":  tcpConn.RemoteAddr(),
	}).Info("SSH connection established")

	// Step 2: Look up VM in Redis
	binding, err := lookupVM(ctx, redisClient, userID)
	if err != nil {
		log.WithFields(log.Fields{
			"user_id": userID,
			"error":   err,
		}).Warn("VM lookup failed")
		sshConn.Close()
		return
	}

	if binding.Status != "running" {
		log.WithFields(log.Fields{
			"user_id": userID,
			"status":  binding.Status,
		}).Warn("VM is not running")
		sshConn.Close()
		return
	}

	// Step 3: Connect to VM's SSH
	// Use per-user password from Redis if available, otherwise fall back to default
	effectivePass := vmPass
	if binding.SSHPassword != "" {
		effectivePass = binding.SSHPassword
	}
	vmAddr := fmt.Sprintf("%s:22", binding.GetVMIP())
	vmConfig := &ssh.ClientConfig{
		User: vmUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(effectivePass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Internal VPC — trusted
		Timeout:         10 * time.Second,
	}

	vmSSHConn, err := ssh.Dial("tcp", vmAddr, vmConfig)
	if err != nil {
		log.WithFields(log.Fields{
			"user_id": userID,
			"vm_addr": vmAddr,
			"error":   err,
		}).Error("Failed to connect to VM SSH")
		sshConn.Close()
		return
	}
	defer vmSSHConn.Close()

	log.WithFields(log.Fields{
		"user_id": userID,
		"vm_ip":   binding.GetVMIP(),
	}).Info("Connected to VM, proxying session")

	// Step 4: Discard global requests on the client side
	go ssh.DiscardRequests(reqs)

	// Step 5: Proxy channels
	for newChannel := range chans {
		go proxyChannel(newChannel, vmSSHConn, userID)
	}

	log.WithField("user_id", userID).Info("SSH session ended")
}

// proxyChannel forwards an SSH channel (session, direct-tcpip, etc.) to the VM.
func proxyChannel(newChannel ssh.NewChannel, vmConn *ssh.Client, userID string) {
	channelType := newChannel.ChannelType()

	// Open corresponding channel on the VM
	vmChannel, vmReqs, err := vmConn.OpenChannel(channelType, newChannel.ExtraData())
	if err != nil {
		log.WithFields(log.Fields{
			"user_id":      userID,
			"channel_type": channelType,
			"error":        err,
		}).Warn("Failed to open VM channel")
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	clientChannel, clientReqs, err := newChannel.Accept()
	if err != nil {
		log.WithError(err).Warn("Failed to accept client channel")
		vmChannel.Close()
		return
	}

	// Proxy requests (pty-req, shell, exec, env, window-change, etc.)
	go proxyRequests(clientReqs, vmChannel)
	go proxyRequests(vmReqs, clientChannel)

	// Proxy data bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(vmChannel, clientChannel)
		vmChannel.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientChannel, vmChannel)
		clientChannel.CloseWrite()
	}()

	wg.Wait()
	vmChannel.Close()
	clientChannel.Close()
}

// proxyRequests forwards SSH requests (PTY, shell, exec, window-change, etc.)
func proxyRequests(in <-chan *ssh.Request, out ssh.Channel) {
	for req := range in {
		ok, err := out.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

// lookupVM retrieves VM binding from Redis.
func lookupVM(ctx context.Context, client *redis.Client, userID string) (*VMBinding, error) {
	data, err := client.Get(ctx, vmBindingPrefix+userID).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("no VM found for user %q", userID)
	}
	if err != nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}

	var binding VMBinding
	if err := json.Unmarshal([]byte(data), &binding); err != nil {
		return nil, fmt.Errorf("invalid binding data: %w", err)
	}

	return &binding, nil
}

// loadOrGenerateHostKey loads an SSH host key from disk, or generates one.
func loadOrGenerateHostKey(path string) ssh.Signer {
	// Try to load existing key
	keyBytes, err := os.ReadFile(path)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err == nil {
			log.Infof("Loaded host key from %s", path)
			return signer
		}
		log.Warnf("Failed to parse host key %s: %v", path, err)
	}

	// Generate a new ED25519 key
	log.Info("Generating new host key...")
	_, privKey, err := generateED25519Key()
	if err != nil {
		log.Fatalf("Failed to generate host key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Try to save (don't fail if we can't)
	if err := savePrivateKey(path, privKey); err != nil {
		log.Warnf("Could not save host key to %s: %v (using ephemeral key)", path, err)
	} else {
		log.Infof("Saved host key to %s", path)
	}

	return signer
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
