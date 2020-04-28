package htpasswd

import (
	"fmt"

	"github.com/daichitakahashi/crypt"
)

type cryptPassword struct {
	salt    string
	crypted string
}

// AcceptCrypt :
func AcceptCrypt(src string) (EncodedPasswd, error) {
	return &cryptPassword{src[:2], src}, nil
}

// RejectCrypt :
func RejectCrypt(src string) (EncodedPasswd, error) {
	return nil, fmt.Errorf("crypt password rejected: %s", src)
}

func (p *cryptPassword) MatchesPassword(pw string) bool {
	crypted := crypt.Crypt(pw, p.salt)
	return constantTimeEquals(crypted, p.crypted)
}
