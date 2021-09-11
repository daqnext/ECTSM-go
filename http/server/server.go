package server

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"github.com/daqnext/ECTSM-go/utils"
	"github.com/daqnext/go-fast-cache"
	"net/http"
)

type EctHttpServer struct {
	PrivateKey *ecdsa.PrivateKey
	Cache      *go_fast_cache.LocalCache
}

func New(privateKeyBase64Str string) (*EctHttpServer, error) {
	hs := &EctHttpServer{}

	privateKey, err := utils.StrBase64ToPrivateKey(privateKeyBase64Str)
	if err != nil {
		return nil, err
	}
	hs.PrivateKey = privateKey

	lc := go_fast_cache.New()
	hs.Cache = lc

	return hs, nil
}

func (hs *EctHttpServer) CheckHeader(header http.Header) (symmetricKey []byte, timeStamp int64, e error) {
	//ecs
	ecs, exist := header["Ecs"]
	if !exist {
		e = errors.New("ecs not exist")
		return nil, 0, e
	}
	if len(ecs) < 1 || ecs[0] == "" {
		e = errors.New("ecs error")
		return nil, 0, e
	}
	//try to get from cache
	ecsBase64Str := ecs[0]
	ecsByte, _, exist := hs.Cache.Get(ecsBase64Str)
	if !exist {
		ct, err := base64.StdEncoding.DecodeString(ecsBase64Str)
		if err != nil {
			return nil, 0, err
		}
		symmetricKey, err = utils.ECCDecrypt(hs.PrivateKey, ct)
		if err != nil {
			e = errors.New("ecs decrypt error")
			return nil, 0, e
		}
		hs.Cache.Set(ecsBase64Str, symmetricKey, 3600)
	} else {
		symmetricKey = ecsByte.([]byte)
	}

	//timeStamp
	timeS, exist := header["Timestamp"]
	if !exist {
		e = errors.New("timestamp not exist")
		return symmetricKey, 0, e
	}
	if len(timeS) < 1 || timeS[0] == "" {
		e = errors.New("timestamp error")
		return nil, 0, e
	}
	timeStampBase64Str := timeS[0]
	timeByte, err := base64.StdEncoding.DecodeString(timeStampBase64Str)
	if err != nil {
		e = errors.New("timestamp error")
		return symmetricKey, 0, e
	}
	timeB, err := utils.AESDecrypt(timeByte, symmetricKey)
	if err != nil {
		e = errors.New("sign error")
		return symmetricKey, 0, e
	}
	timeStamp = utils.BytesToInt64(timeB)

	return symmetricKey, timeStamp, nil
}
