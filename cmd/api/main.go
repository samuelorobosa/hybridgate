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

	authGroup := router.Group("/api/v1/auth")
	{
		authGroup.GET("/ping", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{
				"ok":      true,
				"message": "pong",
			})
		})

		authGroup.POST("/login", auth.HandleLogin)
		authGroup.POST("/refresh", auth.HandleRefresh)

		protected := authGroup.Group("")
		protected.Use(auth.RequireAuth())
		{
			protected.POST("/logout", auth.HandleLogout)
			protected.POST("/revoke", auth.RequirePermission("admin:revoke"), auth.HandleRevoke)
		}
	}

	api := router.Group("/api/v1")
	api.Use(auth.RequireAuth())
	{
		api.GET("/files", auth.RequirePermission("file:read"), auth.HandleListFiles)
	}

	log.Println("listening on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("server: %v", err)
	}
}
