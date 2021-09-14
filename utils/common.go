package utils

import (
	"math/rand"
)

func GenRandomKey() string {
	letterRunes := []rune("1234567890abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, 16)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
