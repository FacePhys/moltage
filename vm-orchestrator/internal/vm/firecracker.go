package vm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/facephys/vm-orchestrator/internal/config"
	log "github.com/sirupsen/logrus"
)

// FirecrackerInstance wraps a running Firecracker process.
type FirecrackerInstance struct {
	UserID     string
	SocketPath string
	Process    *os.Process
	Config     VMConfig
}

// VMConfig holds the parameters for launching a Firecracker VM.
type VMConfig struct {
	KernelPath    string
	RootfsPath    string
	DataDrivePath string
	VMIP          string
	GatewayIP     string
	SubnetMask    string
	TapDevice     string
	VCPUCount     int
	MemSizeMiB    int
	SocketPath    string
}

// FirecrackerLauncher handles the low-level Firecracker process management.
type FirecrackerLauncher struct {
	cfg *config.Config
}

// NewFirecrackerLauncher creates a new launcher.
func NewFirecrackerLauncher(cfg *config.Config) *FirecrackerLauncher {
	return &FirecrackerLauncher{cfg: cfg}
}

// Launch starts a Firecracker VM with the given configuration.
// It uses the Firecracker binary directly with a JSON config file,
// which is simpler and more portable than the Go SDK for our use case.
func (fl *FirecrackerLauncher) Launch(ctx context.Context, vmCfg VMConfig) (*FirecrackerInstance, error) {
	// Remove stale socket if it exists
	os.Remove(vmCfg.SocketPath)

	// Build the kernel boot args with network config
	bootArgs := fmt.Sprintf(
		"console=ttyS0 reboot=k panic=1 pci=off ro "+
			"random.trust_cpu=on "+
			"ip=%s::%s:%s::eth0:off "+
			"init=/sbin/init",
		vmCfg.VMIP, vmCfg.GatewayIP, vmCfg.SubnetMask,
	)

	// Write Firecracker config JSON
	configJSON := fmt.Sprintf(`{
  "boot-source": {
    "kernel_image_path": %q,
    "boot_args": %q
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": %q,
      "is_root_device": true,
      "is_read_only": false
    },
    {
      "drive_id": "data",
      "path_on_host": %q,
      "is_root_device": false,
      "is_read_only": false
    }
  ],
  "machine-config": {
    "vcpu_count": %d,
    "mem_size_mib": %d,
    "smt": false
  },
  "network-interfaces": [
    {
      "iface_id": "eth0",
      "guest_mac": "06:00:AC:10:00:02",
      "host_dev_name": %q
    }
  ]
}`,
		vmCfg.KernelPath,
		bootArgs,
		vmCfg.RootfsPath,
		vmCfg.DataDrivePath,
		vmCfg.VCPUCount,
		vmCfg.MemSizeMiB,
		vmCfg.TapDevice,
	)

	// Write config to a temp file
	configPath := vmCfg.SocketPath + ".config.json"
	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		return nil, fmt.Errorf("failed to write firecracker config: %w", err)
	}

	// Start Firecracker process
	cmd := exec.CommandContext(ctx,
		fl.cfg.FirecrackerBin,
		"--api-sock", vmCfg.SocketPath,
		"--config-file", configPath,
	)

	// Redirect stdout/stderr to log files
	logFile, err := os.Create(vmCfg.SocketPath + ".log")
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %w", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Set process group for clean shutdown
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("failed to start firecracker: %w", err)
	}

	log.WithFields(log.Fields{
		"pid":    cmd.Process.Pid,
		"socket": vmCfg.SocketPath,
		"vm_ip":  vmCfg.VMIP,
	}).Info("Firecracker VM started")

	return &FirecrackerInstance{
		SocketPath: vmCfg.SocketPath,
		Process:    cmd.Process,
		Config:     vmCfg,
	}, nil
}

// Stop gracefully shuts down a Firecracker VM by sending SIGTERM,
// then SIGKILL if it doesn't exit within 5 seconds.
func (fl *FirecrackerLauncher) Stop(instance *FirecrackerInstance) error {
	if instance == nil || instance.Process == nil {
		return nil
	}

	pid := instance.Process.Pid

	// Send SIGTERM first
	if err := instance.Process.Signal(syscall.SIGTERM); err != nil {
		log.WithError(err).WithField("pid", pid).Warn("SIGTERM failed, trying SIGKILL")
		if err := instance.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill firecracker process %d: %w", pid, err)
		}
	}

	// Wait for process to exit
	state, err := instance.Process.Wait()
	if err != nil {
		log.WithError(err).WithField("pid", pid).Warn("Error waiting for firecracker exit")
	} else {
		log.WithFields(log.Fields{
			"pid":    pid,
			"status": state.String(),
		}).Info("Firecracker VM stopped")
	}

	// Cleanup socket and config
	os.Remove(instance.SocketPath)
	os.Remove(instance.SocketPath + ".config.json")
	os.Remove(instance.SocketPath + ".log")

	return nil
}
