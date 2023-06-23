package cardhandler

import (
	"encoding/json"
	authpolicies "example/web-service-gin/auth/auth-policies"
	"example/web-service-gin/db"
	"example/web-service-gin/keys"
	"fmt"

	"github.com/biscuit-auth/biscuit-go"
	"github.com/biscuit-auth/biscuit-go/parser"
	"github.com/gin-gonic/gin"
)

type TokenClaims struct {
	CustomerID string `json:"customer_id"`
	MemberID   string `json:"member_id"`
	UserID     string `json:"user_id"`
	Role       string `json:"role"`
}

type CardHandler struct {
	serviceBiscuit biscuit.Biscuit
	authorizer     biscuit.Authorizer
	claims         TokenClaims
}

func NewCardHandler(b biscuit.Biscuit) CardHandler {
	return CardHandler{
		serviceBiscuit: b,
	}
}

func (h *CardHandler) Process(c *gin.Context) {
	h.AuthMiddleware(c.Request.Header.Get("token")) // this will be taken care by the package

	/* we register custom facts specific to the endpoint */
	h.RegisterEndpointFacts()
	/* we load relationship data from DB and add facts if needed */
	h.RegisterOwnershipData()
	/* get authorizer for the needed policy */

	fmt.Println(h.authorizer.PrintWorld())

	/* authorize request */
	if err := h.authorizer.Authorize(); err != nil {
		fmt.Printf("failed authorizing token: %v\n", err)
	} else {
		fmt.Println("success authorizing token")
	}

	c.Done()
}

func (h *CardHandler) AuthMiddleware(tokenString string) {
	authorizer, err := h.serviceBiscuit.Authorizer(keys.PublicRoot)
	if err != nil {
		panic(err)
	}

	h.authorizer = authorizer

	/* we load all auth data from the token */
	h.RegisterTokenClaims(tokenString)
	/* we load custom role permissions that were assigned to the user */
	h.RegisterCustomPermissions()
}

func (h *CardHandler) RegisterTokenClaims(tokenString string) {
	claims := TokenClaims{}
	json.Unmarshal([]byte(tokenString), &claims)
	fmt.Printf(`claims: %+v`, claims)
	h.claims = claims

	h.authorizer.AddFact(parser.New().Must().Fact(fmt.Sprintf(`user("%s", "%s")`, claims.UserID, claims.Role)))
}

func (h *CardHandler) RegisterEndpointFacts() {
	h.authorizer.AddFact(parser.New().Must().Fact(`operation("card:write")`))
	h.authorizer.AddFact(parser.New().Must().Fact(`card("my-card-id")`))
	h.authorizer.AddPolicy(authpolicies.IfHasRightToPerformOperation)
}

func (h *CardHandler) RegisterCustomPermissions() {
	fmt.Printf(`RegisterCustomPermissions -> claims: %+v`, h.claims)
	permissions := db.GetCustomPermissions(h.claims.UserID)

	fmt.Printf(`permissions %+v`, permissions)

	if len(permissions) > 0 {
		println("adding custom permissions...")
		permissionsString := ""
		for i, p := range permissions {
			permissionsString = permissionsString + fmt.Sprintf(`"%s"`, p)
			if i != len(permissions)-1 {
				permissionsString = permissionsString + ","
			}
		}

		h.authorizer.AddFact(parser.New().Must().Fact(fmt.Sprintf(`custom_permissions([%s])`, permissionsString)))
	}
}

func (h *CardHandler) RegisterOwnershipData() {
	isOwner := db.GetOwnershipData(h.claims.UserID, "my-card-id")
	if isOwner {
		h.authorizer.AddFact(parser.New().Must().Fact(fmt.Sprintf(`card_owner("%s", "my-card-id")`, h.claims.UserID)))
	}
}
