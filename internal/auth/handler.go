package auth

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type loginData struct {
	AccessToken string   `json:"access_token"`
	ExpiresIn   int64    `json:"expires_in"`
	Permissions []string `json:"permissions"`
}

type loginResponse struct {
	OK      bool       `json:"ok"`
	Message string     `json:"message"`
	Data    *loginData `json:"data"`
}

func setRefreshCookie(ctx *gin.Context, refreshToken string) {
	ctx.SetCookie(
		"refresh_token",
		refreshToken,
		int(refreshTokenTTL.Seconds()),
		"/api/v1/auth/refresh",
		"",
		false,
		true,
	)
}

func clearRefreshCookie(ctx *gin.Context) {
	ctx.SetCookie(
		"refresh_token",
		"",
		-1,
		"/api/v1/auth/refresh",
		"",
		false,
		true,
	)
}

func writeLoginSuccess(ctx *gin.Context, result *LoginResult, setCookie bool) {
	if setCookie {
		setRefreshCookie(ctx, result.RefreshToken)
	}
	ctx.JSON(http.StatusOK, loginResponse{
		OK:      true,
		Message: "Login Successful",
		Data: &loginData{
			AccessToken: result.AccessToken,
			ExpiresIn:   result.ExpiresIn,
			Permissions: result.Permissions,
		},
	})
}

func HandleLogin(ctx *gin.Context) {
	var loginReq struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	err := ctx.ShouldBindJSON(&loginReq)
	if err != nil {
		log.Printf("login bind error: %v", err)

		var verrs validator.ValidationErrors
		if errors.As(err, &verrs) {
			details := make([]gin.H, 0, len(verrs))
			for _, fe := range verrs {
				details = append(details, gin.H{
					"tag":   fe.Tag(),
					"error": fe.Error(),
				})
			}
			ctx.JSON(http.StatusBadRequest, gin.H{
				"ok":      false,
				"message": "validation failed",
				"errors":  details,
			})
			return
		}

		ctx.JSON(http.StatusBadRequest, gin.H{
			"ok":      false,
			"message": "invalid request format",
		})
		return
	}

	result, err := LoginUser(LoginInput{
		Email:    loginReq.Email,
		Password: loginReq.Password,
	})

	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"ok":      false,
				"message": "invalid credentials",
			})
			return
		}
		log.Printf("login service error: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"ok":      false,
			"message": "something went wrong",
		})
		return
	}

	writeLoginSuccess(ctx, result, true)
}

func HandleRefresh(ctx *gin.Context) {
	refreshToken, err := ctx.Cookie("refresh_token")
	if err != nil || refreshToken == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"ok":      false,
			"message": "missing refresh token",
		})
		return
	}

	result, err := RefreshSession(refreshToken)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"ok":      false,
				"message": "invalid refresh token",
			})
			return
		}
		log.Printf("refresh service error: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"ok":      false,
			"message": "something went wrong",
		})
		return
	}

	writeLoginSuccess(ctx, result, true)
}

func HandleRevoke(ctx *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"ok":      false,
			"message": "validation failed",
		})
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx.Request.Context(), 3*time.Second)
	defer cancel()

	if err := RevokeUser(reqCtx, RevokeInput{Email: req.Email}); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			ctx.JSON(http.StatusNotFound, gin.H{
				"ok":      false,
				"message": "user not found",
			})
			return
		}
		log.Printf("revoke service error: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"ok":      false,
			"message": "something went wrong",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"message": "user access revoked",
	})
}

func HandleLogout(ctx *gin.Context) {
	ac, ok := GetAuthContext(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"ok":      false,
			"message": "unauthorized",
		})
		return
	}

	refreshToken, _ := ctx.Cookie("refresh_token")

	reqCtx, cancel := context.WithTimeout(ctx.Request.Context(), 3*time.Second)
	defer cancel()

	if err := LogoutUser(reqCtx, ac.JTI, refreshToken); err != nil {
		log.Printf("logout service error: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"ok":      false,
			"message": "something went wrong",
		})
		return
	}

	clearRefreshCookie(ctx)
	ctx.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"message": "logged out",
	})
}

func HandleListFiles(ctx *gin.Context) {
	ac, _ := GetAuthContext(ctx)
	ctx.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"message": "files retrieved",
		"data": gin.H{
			"files": []gin.H{
				{"name": "report.pdf", "permission": "file:read"},
				{"name": "budget.xlsx", "permission": "file:write"},
			},
			"requested_by": ac.Email,
		},
	})
}
