package authfacts

import (
	"github.com/biscuit-auth/biscuit-go/parser"
)

var AdminFact = parser.New().Must().Fact(`role("admin", ["card:read", "card:write"])`)

var BuyerFact = parser.New().Must().Fact(`role("buyer", ["card:read"])`)
