package authpolicies

import "github.com/biscuit-auth/biscuit-go/parser"

/* this will stay in the package */
var IfHasRightToPerformOperation = parser.New().Must().Policy(`allow if right($op), operation($op)`)
