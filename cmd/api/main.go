package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/samuelorobosa/hybridgate/internal/auth"
	"github.com/samuelorobosa/hybridgate/internal/platform/database"
	"github.com/samuelorobosa/hybridgate/internal/platform/redis"
)

func main() {
	database.InitDB()
	redis.Init()

	router := gin.Default()

	{
		v1 := router.Group("/api/v1/auth")

		v1.GET("/ping", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{
				"ok":      true,
				"message": "pong",
			})
		})

		v1.POST("/login", auth.HandleLogin)
	}

	log.Println("listening on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("server: %v", err)
	}
}
