package keys

import (
	"crypto/ed25519"
	"crypto/rand"
)

var (
	PublicRoot, PrivateRoot, _ = ed25519.GenerateKey(rand.Reader)
)
