module github.com/facephys/vm-orchestrator

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/redis/go-redis/v9 v9.5.1
	github.com/firecracker-microvm/firecracker-go-sdk v1.0.0
	github.com/sirupsen/logrus v1.9.3
	github.com/google/uuid v1.6.0
)

replace github.com/ugorji/go => github.com/ugorji/go/codec v1.2.11
