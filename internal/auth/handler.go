package auth

import (
	"errors"
	"log"
	"net/http"

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

	// set refresh cookie
	setRefreshCookie(ctx, result.RefreshToken)

	// return login response
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
