package utils

import (
	"encoding/json"
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

func InterfaceToByte(obj interface{}) ([]byte, error) {
	switch obj.(type) {
	case string:
		return []byte(obj.(string)), nil
	case []byte:
		return obj.([]byte), nil
	default:
		if obj == nil {
			return nil, nil
		} else {
			objStringByte, err := json.Marshal(obj)
			if err != nil {
				return nil, err
			}
			return objStringByte, nil
		}
	}
}
