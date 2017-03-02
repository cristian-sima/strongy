package strongy

import (
	"bytes"
	"crypto/rand"
	"regexp"
)

const (
	characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+,.?/:;{}[]~"
)

// Power evaluates the level of power
type Power int

const (
	// Horrible is level of password
	Horrible Power = iota
	// Weak is level of password
	Weak
	// Medium is level of password
	Medium
	// Strong is level of password
	Strong
	// Secure is level of password
	Secure
)

func (power Power) String() string {
	switch power {
	case Horrible:
		return "Horrible"
	case Weak:
		return "Weak"
	case Medium:
		return "Medium"
	case Strong:
		return "Strong"
	}
	return "Secure"
}

// Password encapsulates the data about the password
type Password struct {
	Pass            string
	Length          int
	score           int
	ContainsUpper   bool
	ContainsLower   bool
	ContainsNumber  bool
	ContainsSpecial bool
}

// SaltConf is the salt
type SaltConf struct {
	Length int
}

// New is used when a user enters a password as well as the
// being called from the GeneratePassword function.
func New(password string) *Password {
	return &Password{Pass: password, Length: len(password)}
}

// GeneratePassword will generate and return a password as a string and as a
// byte slice of the given length.
func GeneratePassword(length int) *Password {
	passwordBuffer := new(bytes.Buffer)
	randBytes := make([]byte, length)

	if _, err := rand.Read(randBytes); err == nil {
		for j := 0; j < length; j++ {
			tmpIndex := int(randBytes[j]) % len(characters)
			char := characters[tmpIndex]
			passwordBuffer.WriteString(string(char))
		}
	}
	return New(passwordBuffer.String())
}

// GenerateVeryStrongPassword will generate a "Very Strong" password.
func GenerateVeryStrongPassword(length int) *Password {
	for {
		p := GeneratePassword(length)
		p.ProcessPassword()
		if p.score == 4 {
			return p
		}
	}
}

// getRandomBytes will generate random bytes.  This is for internal
// use in the library itself.
func getRandomBytes(length int) []byte {
	randomData := make([]byte, length)
	if _, err := rand.Read(randomData); err != nil {
		panic(err)
	}
	return randomData
}

// GetLength will provide the length of the password.  This method is
// being put on the password struct in case someone decides not to
// do a complexity check.
func (p *Password) GetLength() int {
	return p.Length
}

// ProcessPassword will parse the password and populate the Password struct attributes.
func (p *Password) ProcessPassword() {
	
	const (
		defaultPassword = "P@r0la_m3A"
		)
	
	matchLower := regexp.MustCompile(`[a-z]`)
	matchUpper := regexp.MustCompile(`[A-Z]`)
	matchNumber := regexp.MustCompile(`[0-9]`)
	matchSpecial := regexp.MustCompile(`[\!\@\#\$\%\^\&\*\(\\\)\-_\=\+\,\.\?\/\:\;\{\}\[\]~]`)
	
	if p.Pass != defaultPassword && p.Length > 6 {
		if matchLower.MatchString(p.Pass) {
			p.ContainsLower = true
			p.score++
		}
		if matchUpper.MatchString(p.Pass) {
			p.ContainsUpper = true
			p.score++
		}
		if matchNumber.MatchString(p.Pass) {
			p.ContainsNumber = true
			p.score++
		}
		if matchSpecial.MatchString(p.Pass) {
			p.ContainsSpecial = true
			p.score++
		}
	}
}

// Getscore will provide the score of the password.
func (p *Password) Getscore() int {
	return p.score
}

// Power provides the rating for the password.
func (p *Password) Power() Power {
	return Power(p.score)
}
