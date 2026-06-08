package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func RequireAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		header := ctx.GetHeader("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"ok":      false,
				"message": "missing or invalid authorization header",
			})
			return
		}

		tokenString := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		parsed, err := ParseAccessToken(tokenString)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"ok":      false,
				"message": "invalid access token",
			})
			return
		}

		reqCtx, cancel := context.WithTimeout(ctx.Request.Context(), 2*time.Second)
		defer cancel()

		blacklisted, err := IsJTIBlacklisted(reqCtx, parsed.JTI)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"ok":      false,
				"message": "something went wrong",
			})
			return
		}
		if blacklisted {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"ok":      false,
				"message": "access revoked",
			})
			return
		}

		revoked, err := IsUserRevoked(reqCtx, parsed.UserCUID)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"ok":      false,
				"message": "something went wrong",
			})
			return
		}
		if revoked {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"ok":      false,
				"message": "access revoked",
			})
			return
		}

		setAuthContext(ctx, AuthContext{
			UserCUID:    parsed.UserCUID,
			Email:       parsed.Email,
			Permissions: parsed.Permissions,
			JTI:         parsed.JTI,
		})
		ctx.Next()
	}
}

func RequirePermission(slug string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ac, ok := GetAuthContext(ctx)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"ok":      false,
				"message": "unauthorized",
			})
			return
		}
		if !hasPermission(ac.Permissions, slug) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"ok":      false,
				"message": "insufficient permissions",
			})
			return
		}
		ctx.Next()
	}
}
