package authfacts

import (
	"github.com/biscuit-auth/biscuit-go/parser"
)

/* this will stay in the service */
var AdminFact = parser.New().Must().Fact(`role("admin", ["card:read", "card:write"])`)

/* this will stay in the service */
var BuyerFact = parser.New().Must().Fact(`role("buyer", ["card:read"])`)
