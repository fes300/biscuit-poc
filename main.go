package main

import (
	authfacts "example/web-service-gin/auth/auth-facts"
	authrules "example/web-service-gin/auth/auth-rules"
	cardhandler "example/web-service-gin/card-handler"
	"example/web-service-gin/keys"

	"github.com/biscuit-auth/biscuit-go"
	"github.com/gin-gonic/gin"
)

func main() {
	serviceBiscuit := registerServicePolicies()
	router := gin.Default()
	handler := cardhandler.NewCardHandler(serviceBiscuit)
	router.POST("/write-card/my-card-id", handler.Process)

	router.Run("localhost:8080")
}

/* this will stay in the service */
func registerServicePolicies() biscuit.Biscuit {
	builder := biscuit.NewBuilder(keys.PrivateRoot)

	builder.AddAuthorityFact(authfacts.AdminFact)
	builder.AddAuthorityFact(authfacts.BuyerFact)
	builder.AddAuthorityRule(authrules.IfUserRoleAllowsOperation)
	builder.AddAuthorityRule(authrules.IfUserHasCustomPermissionForOperation)
	builder.AddAuthorityRule(authrules.IfUserIsOwnerHeCanWriteCard)

	serviceBiscuit, err := builder.Build()
	if err != nil {
		panic(err)
	}

	return *serviceBiscuit
}
