package api

import (
	"net/http"

	"github.com/facephys/vm-orchestrator/internal/models"
	"github.com/facephys/vm-orchestrator/internal/vm"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handler holds route handlers with a reference to the VM Manager.
type Handler struct {
	manager *vm.Manager
}

// NewHandler creates a new API handler.
func NewHandler(mgr *vm.Manager) *Handler {
	return &Handler{manager: mgr}
}

// CreateVM handles POST /api/v1/vms
func (h *Handler) CreateVM(c *gin.Context) {
	var req models.CreateVMRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	log.WithField("user_id", req.UserID).Info("CreateVM request")

	info, err := h.manager.CreateVM(c.Request.Context(), req)
	if err != nil {
		log.WithError(err).Error("CreateVM failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, info)
}

// GetVM handles GET /api/v1/vms/:user_id
func (h *Handler) GetVM(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	info, err := h.manager.GetVMInfo(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if info == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "VM not found"})
		return
	}

	c.JSON(http.StatusOK, info)
}

// StopVM handles POST /api/v1/vms/:user_id/stop
func (h *Handler) StopVM(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	if err := h.manager.StopVM(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

// DestroyVM handles DELETE /api/v1/vms/:user_id
func (h *Handler) DestroyVM(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	if err := h.manager.DestroyVM(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "destroyed"})
}

// ListVMs handles GET /api/v1/vms
func (h *Handler) ListVMs(c *gin.Context) {
	vms, err := h.manager.ListVMs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.VMListResponse{
		VMs:   vms,
		Total: len(vms),
	})
}

// StartVM handles POST /api/v1/vms/:user_id/start (restart a stopped VM)
func (h *Handler) StartVM(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	// Re-create the VM (provisions new TAP/IP, reuses existing rootfs+data)
	info, err := h.manager.CreateVM(c.Request.Context(), models.CreateVMRequest{
		UserID: userID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, info)
}

// ChangePassword handles POST /api/v1/vms/:user_id/passwd
func (h *Handler) ChangePassword(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	if err := h.manager.ChangePassword(c.Request.Context(), userID, req.NewPassword); err != nil {
		log.WithError(err).WithField("user_id", userID).Error("ChangePassword failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "password_changed"})
}
