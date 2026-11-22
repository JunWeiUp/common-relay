package plugin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Account passwords are stored as "scrypt$N$r$p$<salt b64>$<hash b64>".
// Legacy rows hold a bare 64-hex SHA-256 and remain verifiable.
const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", scryptN, scryptR, scryptP,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

func verifyStoredSecret(plain, stored string) bool {
	if plain == "" {
		return false
	}
	if !strings.HasPrefix(stored, "scrypt$") {
		return SecretMatchesHash(plain, stored)
	}
	parts := strings.Split(stored, "$")
	if len(parts) != 6 {
		return false
	}
	n, err1 := strconv.Atoi(parts[1])
	r, err2 := strconv.Atoi(parts[2])
	p, err3 := strconv.Atoi(parts[3])
	salt, err4 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err5 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || n > 1<<20 || r > 32 || p > 16 {
		return false
	}
	got, err := scrypt.Key([]byte(plain), salt, n, r, p, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// IsSaltedHash reports whether stored uses the salted scheme (for status views).
func IsSaltedHash(stored string) bool { return strings.HasPrefix(stored, "scrypt$") }
