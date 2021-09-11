package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func GenSecp256k1KeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(crypto.S256(), rand.Reader)
}

func PublicKeyToString(pub *ecdsa.PublicKey) string {
	priKeyByte := elliptic.Marshal(crypto.S256(), pub.X, pub.Y)
	return base64.StdEncoding.EncodeToString(priKeyByte)
}

func PrivateKeyToString(priv *ecdsa.PrivateKey) string {
	pubKeyByte := math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
	return base64.StdEncoding.EncodeToString(pubKeyByte)
}

func StrBase64ToPrivateKey(stringd string) (*ecdsa.PrivateKey, error) {
	d, err := base64.StdEncoding.DecodeString(stringd)
	if err != nil {
		return nil, err
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = crypto.S256()
	if 8*len(d) != priv.Params().BitSize {
		return nil, errors.New("invalid length")
	}
	priv.D = new(big.Int).SetBytes(d)

	if priv.D.Sign() <= 0 {
		return nil, errors.New("zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

func StrBase64ToPublicKey(pub string) (*ecdsa.PublicKey, error) {
	if len(pub) == 0 {
		return nil, errors.New("input error")
	}
	pubkeyrawstr, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return nil, errors.New("wrong input")
	}

	x, y := elliptic.Unmarshal(crypto.S256(), pubkeyrawstr)
	return &ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}, nil
}

func ECCEncrypt(ecdsaPublicKey *ecdsa.PublicKey, rawMsg []byte) ([]byte, error) {
	publicKey := ecies.ImportECDSAPublic(ecdsaPublicKey)
	if publicKey.X == nil || publicKey.Y == nil {
		return nil, errors.New("invalid key")
	}
	ct, err := ecies.Encrypt(rand.Reader, publicKey, rawMsg, nil, nil)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func ECCDecrypt(prik *ecdsa.PrivateKey, ct []byte) ([]byte, error) {
	ecies_prv2 := ecies.ImportECDSA(prik)
	return ecies_prv2.Decrypt(ct, nil, nil)
}

func GenAndPrintEccKeyPair() (privateKeyBase64Str string, publicKeyBase64Str string, err error) {
	privateKey, err := GenSecp256k1KeyPair()
	if err != nil {
		return "", "", err
	}
	privateKeyBase64Str = PrivateKeyToString(privateKey)
	publicKey := &privateKey.PublicKey
	publicKeyBase64Str = PublicKeyToString(publicKey)

	log.Println("private key base64:", privateKeyBase64Str)
	log.Println("public key base64:", publicKeyBase64Str)

	return privateKeyBase64Str, publicKeyBase64Str, nil
}
