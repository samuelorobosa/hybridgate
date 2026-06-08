package auth

import (
	"github.com/gin-gonic/gin"
)

const (
	ctxUserCUID     = "authUserCUID"
	ctxEmail        = "authEmail"
	ctxPermissions  = "authPermissions"
	ctxJTI          = "authJTI"
)

type AuthContext struct {
	UserCUID    string
	Email       string
	Permissions []string
	JTI         string
}

func setAuthContext(ctx *gin.Context, ac AuthContext) {
	ctx.Set(ctxUserCUID, ac.UserCUID)
	ctx.Set(ctxEmail, ac.Email)
	ctx.Set(ctxPermissions, ac.Permissions)
	ctx.Set(ctxJTI, ac.JTI)
}

func GetAuthContext(ctx *gin.Context) (AuthContext, bool) {
	userCUID, ok := ctx.Get(ctxUserCUID)
	if !ok {
		return AuthContext{}, false
	}
	email, _ := ctx.Get(ctxEmail)
	perms, _ := ctx.Get(ctxPermissions)
	jti, _ := ctx.Get(ctxJTI)

	return AuthContext{
		UserCUID:    userCUID.(string),
		Email:       email.(string),
		Permissions: perms.([]string),
		JTI:         jti.(string),
	}, true
}

func hasPermission(permissions []string, slug string) bool {
	for _, p := range permissions {
		if p == slug {
			return true
		}
	}
	return false
}
