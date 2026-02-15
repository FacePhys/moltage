package models

import "time"

// VMStatus represents the current state of a MicroVM.
type VMStatus string

const (
	VMStatusProvisioning VMStatus = "provisioning"
	VMStatusRunning      VMStatus = "running"
	VMStatusStopped      VMStatus = "stopped"
	VMStatusError        VMStatus = "error"
)

// VMInfo holds the full state of a user's MicroVM.
type VMInfo struct {
	UserID         string         `json:"user_id"`
	Status         VMStatus       `json:"status"`
	VMIP           string         `json:"vm_ip"`
	WebhookURL     string         `json:"webhook_url"`
	TapDevice      string         `json:"tap_device"`
	SocketPath     string         `json:"socket_path"`
	PID            int            `json:"pid,omitempty"`
	SSHPassword    string         `json:"ssh_password,omitempty"`
	ResourceLimits ResourceLimits `json:"resource_limits"`
	CreatedAt      time.Time      `json:"created_at"`
	StoppedAt      *time.Time     `json:"stopped_at,omitempty"`
	ErrorMessage   string         `json:"error_message,omitempty"`
}

// ResourceLimits defines the compute resources for a VM.
type ResourceLimits struct {
	VCPUCount  int `json:"vcpu_count"`
	MemSizeMiB int `json:"mem_size_mib"`
}

// CreateVMRequest is the payload for creating a new VM.
type CreateVMRequest struct {
	UserID         string          `json:"user_id" binding:"required"`
	ResourceLimits *ResourceLimits `json:"resource_limits,omitempty"`
}

// CreateVMResponse is returned after a VM is created.
type CreateVMResponse struct {
	VMInfo
}

// VMListResponse wraps a list of VMs.
type VMListResponse struct {
	VMs   []VMInfo `json:"vms"`
	Total int      `json:"total"`
}

// ChangePasswordRequest is the payload for changing a VM's SSH password.
type ChangePasswordRequest struct {
	NewPassword string `json:"new_password" binding:"required,min=6"`
}
