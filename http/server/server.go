package server

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net/http"

	ecthttp "github.com/daqnext/ECTSM-go/http"
	"github.com/daqnext/ECTSM-go/utils"
	go_fast_cache "github.com/daqnext/go-fast-cache"
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

func (hs *EctHttpServer) HandlePost(header http.Header, body io.ReadCloser) (symmetricKey []byte, decryptedBody []byte, token []byte, e error) {

	ecs, exist := header["Ectm_key"]
	if !exist || len(ecs) < 1 || ecs[0] == "" {
		return nil, nil, nil, errors.New("ecs not exist")
	}

	//try to get from cache
	ecsBase64Str := ecs[0]
	ecsByte, _, exist := hs.Cache.Get(ecsBase64Str)
	if !exist {
		ct, err := base64.StdEncoding.DecodeString(ecsBase64Str)
		if err != nil {
			return nil, nil, nil, err
		}
		symmetricKey, err = utils.ECCDecrypt(hs.PrivateKey, ct)
		if err != nil {
			return nil, nil, nil, errors.New("ecs decrypt error")
		}
		hs.Cache.Set(ecsBase64Str, symmetricKey, 3600)
	} else {
		symmetricKey = ecsByte.([]byte)
	}

	//check header
	token, err := ecthttp.DecryptECTMHeader(header, symmetricKey)
	if err != nil {
		return nil, nil, nil, err
	}

	bodybyte, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, nil, token, errors.New("body error")
	}

	decryptBody, err := ecthttp.DecryptBody(bodybyte, symmetricKey)
	if err != nil {
		return nil, nil, token, errors.New("decrypt error")
	}

	return symmetricKey, decryptBody, token, nil

}

func (hs *EctHttpServer) HandleGet(header http.Header) (symmetricKey []byte, token []byte, e error) {

	ecs, exist := header["Ectm_key"]
	if !exist || len(ecs) < 1 || ecs[0] == "" {
		return nil, nil, errors.New("ecs not exist")
	}

	//try to get from cache
	ecsBase64Str := ecs[0]
	ecsByte, _, exist := hs.Cache.Get(ecsBase64Str)
	if !exist {
		ct, err := base64.StdEncoding.DecodeString(ecsBase64Str)
		if err != nil {
			return nil, nil, err
		}
		symmetricKey, err = utils.ECCDecrypt(hs.PrivateKey, ct)
		if err != nil {
			return nil, nil, errors.New("ecs decrypt error")
		}
		hs.Cache.Set(ecsBase64Str, symmetricKey, 3600)
	} else {
		symmetricKey = ecsByte.([]byte)
	}

	//check header
	token, err := ecthttp.DecryptECTMHeader(header, symmetricKey)
	if err != nil {
		return nil, nil, err
	}

	return symmetricKey, token, nil

}
