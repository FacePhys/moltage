package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/facephys/vm-orchestrator/internal/config"
	"github.com/facephys/vm-orchestrator/internal/models"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	vmBindingPrefix = "vm:binding:"
	vmDataSizeMB    = 256 // Default data volume size
)

// Manager coordinates all VM lifecycle operations.
type Manager struct {
	cfg        *config.Config
	network    *NetworkManager
	storage    *StorageManager
	launcher   *FirecrackerLauncher
	redis      *redis.Client
	instances  map[string]*FirecrackerInstance // userID -> instance
	mu         sync.RWMutex
}

// NewManager creates a fully initialized VM Manager.
func NewManager(cfg *config.Config, redisClient *redis.Client) (*Manager, error) {
	netMgr, err := NewNetworkManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to init network manager: %w", err)
	}

	return &Manager{
		cfg:       cfg,
		network:   netMgr,
		storage:   NewStorageManager(cfg),
		launcher:  NewFirecrackerLauncher(cfg),
		redis:     redisClient,
		instances: make(map[string]*FirecrackerInstance),
	}, nil
}

// CreateVM provisions and launches a new MicroVM for the given user.
func (m *Manager) CreateVM(ctx context.Context, req models.CreateVMRequest) (*models.VMInfo, error) {
	userID := req.UserID

	// Check if VM already exists
	m.mu.RLock()
	if _, exists := m.instances[userID]; exists {
		m.mu.RUnlock()
		return m.GetVMInfo(ctx, userID)
	}
	m.mu.RUnlock()

	log.WithField("user_id", userID).Info("Provisioning new VM")

	// Set initial status in Redis
	info := &models.VMInfo{
		UserID:    userID,
		Status:    models.VMStatusProvisioning,
		CreatedAt: time.Now(),
		ResourceLimits: models.ResourceLimits{
			VCPUCount:  m.cfg.DefaultVCPU,
			MemSizeMiB: m.cfg.DefaultMemMiB,
		},
	}
	if req.ResourceLimits != nil {
		info.ResourceLimits = *req.ResourceLimits
	}

	if err := m.saveVMInfo(ctx, info); err != nil {
		return nil, fmt.Errorf("failed to save initial VM info: %w", err)
	}

	// Step 1: Allocate IP
	vmIP, err := m.network.AllocateIP(userID)
	if err != nil {
		m.setVMError(ctx, info, fmt.Sprintf("IP allocation failed: %v", err))
		return nil, err
	}
	info.VMIP = vmIP

	// Step 2: Provision storage
	rootfsPath, err := m.storage.ProvisionRootfs(userID)
	if err != nil {
		m.network.ReleaseIP(vmIP)
		m.setVMError(ctx, info, fmt.Sprintf("Rootfs provisioning failed: %v", err))
		return nil, err
	}

	dataPath, err := m.storage.ProvisionDataVolume(userID, vmDataSizeMB)
	if err != nil {
		m.network.ReleaseIP(vmIP)
		m.setVMError(ctx, info, fmt.Sprintf("Data volume provisioning failed: %v", err))
		return nil, err
	}

	// Step 4: Create TAP device
	tapName, err := m.network.CreateTapDevice(vmIP)
	if err != nil {
		m.network.ReleaseIP(vmIP)
		m.setVMError(ctx, info, fmt.Sprintf("TAP creation failed: %v", err))
		return nil, err
	}
	info.TapDevice = tapName

	// Step 5: Setup isolation rules
	if err := m.network.SetupVMIsolation(vmIP); err != nil {
		m.network.DestroyTapDevice(tapName)
		m.network.ReleaseIP(vmIP)
		m.setVMError(ctx, info, fmt.Sprintf("Isolation setup failed: %v", err))
		return nil, err
	}

	// Step 6: Launch Firecracker
	socketPath := m.storage.GetSocketPath(userID)
	instance, err := m.launcher.Launch(ctx, VMConfig{
		KernelPath:    m.cfg.KernelPath,
		RootfsPath:    rootfsPath,
		DataDrivePath: dataPath,
		VMIP:          vmIP,
		GatewayIP:     m.cfg.GatewayIP,
		SubnetMask:    "255.255.255.0", // /24
		TapDevice:     tapName,
		VCPUCount:     info.ResourceLimits.VCPUCount,
		MemSizeMiB:    info.ResourceLimits.MemSizeMiB,
		SocketPath:    socketPath,
	})
	if err != nil {
		m.network.CleanupVMIsolation(vmIP)
		m.network.DestroyTapDevice(tapName)
		m.network.ReleaseIP(vmIP)
		m.setVMError(ctx, info, fmt.Sprintf("Firecracker launch failed: %v", err))
		return nil, err
	}

	// Step 7: Register instance and update status
	m.mu.Lock()
	m.instances[userID] = instance
	m.mu.Unlock()

	info.Status = models.VMStatusRunning
	info.SocketPath = socketPath
	info.PID = instance.Process.Pid
	info.WebhookURL = fmt.Sprintf("http://%s:18789/webhook", vmIP)

	if err := m.saveVMInfo(ctx, info); err != nil {
		log.WithError(err).Error("Failed to save final VM info")
	}

	// Step 8: Wait for VM readiness (Clawdbot webhook endpoint)
	go m.waitForVMReady(ctx, info)

	log.WithFields(log.Fields{
		"user_id": userID,
		"vm_ip":   vmIP,
		"pid":     instance.Process.Pid,
	}).Info("VM provisioned successfully")

	return info, nil
}

// StopVM gracefully stops a user's VM.
func (m *Manager) StopVM(ctx context.Context, userID string) error {
	m.mu.Lock()
	instance, exists := m.instances[userID]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("no running VM for user %s", userID)
	}
	delete(m.instances, userID)
	m.mu.Unlock()

	// Stop Firecracker
	if err := m.launcher.Stop(instance); err != nil {
		log.WithError(err).WithField("user_id", userID).Error("Failed to stop VM")
	}

	// Cleanup networking
	m.network.CleanupVMIsolation(instance.Config.VMIP)
	m.network.DestroyTapDevice(instance.Config.TapDevice)
	m.network.ReleaseIP(instance.Config.VMIP)

	// Update status in Redis
	info, _ := m.GetVMInfo(ctx, userID)
	if info != nil {
		now := time.Now()
		info.Status = models.VMStatusStopped
		info.StoppedAt = &now
		m.saveVMInfo(ctx, info)
	}

	log.WithField("user_id", userID).Info("VM stopped")
	return nil
}

// DestroyVM stops and removes all storage for a user.
func (m *Manager) DestroyVM(ctx context.Context, userID string) error {
	// Stop first if running
	m.mu.RLock()
	_, running := m.instances[userID]
	m.mu.RUnlock()
	if running {
		if err := m.StopVM(ctx, userID); err != nil {
			log.WithError(err).Warn("Error stopping VM during destroy")
		}
	}

	// Cleanup storage
	if err := m.storage.CleanupStorage(userID); err != nil {
		return err
	}

	// Remove from Redis
	m.redis.Del(ctx, vmBindingPrefix+userID)

	log.WithField("user_id", userID).Info("VM destroyed")
	return nil
}

// ChangePassword changes the SSH password for a user's VM.
// It SSHs into the VM and runs chpasswd, then stores the new password in Redis.
func (m *Manager) ChangePassword(ctx context.Context, userID, newPassword string) error {
	info, err := m.GetVMInfo(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get VM info: %w", err)
	}
	if info == nil {
		return fmt.Errorf("no VM found for user %s", userID)
	}
	if info.Status != models.VMStatusRunning {
		return fmt.Errorf("VM is not running (status: %s)", info.Status)
	}

	// Determine current password (use stored one or default)
	currentPass := info.SSHPassword
	if currentPass == "" {
		currentPass = "clawdbot"
	}

	// SSH into the VM and change password
	sshConfig := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password(currentPass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	vmAddr := net.JoinHostPort(info.VMIP, "22")
	client, err := ssh.Dial("tcp", vmAddr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to SSH into VM: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Change password for both 'user' and 'root'
	cmd := fmt.Sprintf("echo 'user:%s\nroot:%s' | chpasswd", newPassword, newPassword)
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to change password: %w", err)
	}

	// Store new password in Redis
	info.SSHPassword = newPassword
	if err := m.saveVMInfo(ctx, info); err != nil {
		return fmt.Errorf("password changed in VM but failed to save to Redis: %w", err)
	}

	log.WithField("user_id", userID).Info("VM password changed successfully")
	return nil
}

// GetVMInfo retrieves VM info from Redis.
func (m *Manager) GetVMInfo(ctx context.Context, userID string) (*models.VMInfo, error) {
	data, err := m.redis.Get(ctx, vmBindingPrefix+userID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis get failed: %w", err)
	}

	var info models.VMInfo
	if err := json.Unmarshal([]byte(data), &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VM info: %w", err)
	}
	return &info, nil
}

// ListVMs returns all active VM infos.
func (m *Manager) ListVMs(ctx context.Context) ([]models.VMInfo, error) {
	keys, err := m.redis.Keys(ctx, vmBindingPrefix+"*").Result()
	if err != nil {
		return nil, fmt.Errorf("redis keys failed: %w", err)
	}

	var vms []models.VMInfo
	for _, key := range keys {
		data, err := m.redis.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		var info models.VMInfo
		if err := json.Unmarshal([]byte(data), &info); err != nil {
			continue
		}
		vms = append(vms, info)
	}
	return vms, nil
}

// --- Internal Helpers ---

func (m *Manager) saveVMInfo(ctx context.Context, info *models.VMInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return m.redis.Set(ctx, vmBindingPrefix+info.UserID, string(data), 0).Err()
}

func (m *Manager) setVMError(ctx context.Context, info *models.VMInfo, errMsg string) {
	info.Status = models.VMStatusError
	info.ErrorMessage = errMsg
	m.saveVMInfo(ctx, info)
	log.WithFields(log.Fields{
		"user_id": info.UserID,
		"error":   errMsg,
	}).Error("VM provisioning failed")
}



// waitForVMReady polls the VM's webhook endpoint until it responds.
func (m *Manager) waitForVMReady(ctx context.Context, info *models.VMInfo) {
	maxAttempts := 60 // 60 * 500ms = 30s
	client := &http.Client{Timeout: 2 * time.Second}

	for i := 0; i < maxAttempts; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		healthURL := fmt.Sprintf("http://%s:18789/health", info.VMIP)
		resp, err := client.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				log.WithField("user_id", info.UserID).Info("VM is ready (Clawdbot responding)")
				return
			}
		}

		time.Sleep(500 * time.Millisecond)
	}

	log.WithField("user_id", info.UserID).Warn("VM readiness check timed out")
}
