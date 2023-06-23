package authpolicies

import "github.com/biscuit-auth/biscuit-go/parser"

var IfHasRightToPerformOperation = parser.New().Must().Policy(`allow if right($op), operation($op)`)
