package api

import (
	"fmt"

	"github.com/facephys/vm-orchestrator/internal/config"
	"github.com/facephys/vm-orchestrator/internal/vm"
	"github.com/gin-gonic/gin"
)

// NewServer creates and configures the Gin HTTP server.
func NewServer(cfg *config.Config, mgr *vm.Manager) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	handler := NewHandler(mgr)

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// VM API routes
	v1 := r.Group("/api/v1")
	{
		vms := v1.Group("/vms")
		{
			vms.POST("", handler.CreateVM)
			vms.GET("", handler.ListVMs)
			vms.GET("/:user_id", handler.GetVM)
			vms.DELETE("/:user_id", handler.DestroyVM)
			vms.POST("/:user_id/stop", handler.StopVM)
			vms.POST("/:user_id/start", handler.StartVM)
			vms.POST("/:user_id/passwd", handler.ChangePassword)
		}
	}

	fmt.Printf("API server configured on %s:%d\n", cfg.Host, cfg.Port)
	return r
}
