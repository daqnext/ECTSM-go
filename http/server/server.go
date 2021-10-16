package server

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	ecthttp "github.com/daqnext/ECTSM-go/http"
	"github.com/daqnext/ECTSM-go/utils"
	locallog "github.com/daqnext/LocalLog/log"
	go_fast_cache "github.com/daqnext/go-fast-cache"
)

type EctHttpServer struct {
	PrivateKey *ecdsa.PrivateKey
	Cache      *go_fast_cache.LocalCache
}

func New(privateKeyBase64Str string, llog *locallog.LocalLog) (*EctHttpServer, error) {
	hs := &EctHttpServer{}

	privateKey, err := utils.StrBase64ToPrivateKey(privateKeyBase64Str)
	if err != nil {
		return nil, err
	}
	hs.PrivateKey = privateKey

	lc := go_fast_cache.New(llog)
	hs.Cache = lc

	return hs, nil
}

func (hs *EctHttpServer) HandlePost(httpRequest *http.Request) *ecthttp.ECTRequest { //(symmetricKey []byte, decryptedBody []byte, token []byte, e error)

	ecs, exist := httpRequest.Header["Ectm_key"]
	if !exist || len(ecs) < 1 || ecs[0] == "" {
		return &ecthttp.ECTRequest{Rq: httpRequest, Token: nil, SymmetricKey: nil, DecryptedBody: nil, Err: errors.New("ecs not exist")}
	}

	var symmetricKey []byte
	//try to get from cache
	ecsBase64Str := ecs[0]
	ecsByte, _, exist := hs.Cache.Get(ecsBase64Str)
	if !exist {
		ct, err := base64.StdEncoding.DecodeString(ecsBase64Str)
		if err != nil {
			return &ecthttp.ECTRequest{Rq: httpRequest, Token: nil, SymmetricKey: nil, DecryptedBody: nil, Err: err}
		}
		symmetricKey, err = utils.ECCDecrypt(hs.PrivateKey, ct)
		if err != nil {
			return &ecthttp.ECTRequest{Rq: httpRequest, Token: nil, SymmetricKey: nil, DecryptedBody: nil, Err: errors.New("ecs decrypt error")}
		}
		hs.Cache.Set(ecsBase64Str, symmetricKey, 3600)
	} else {
		symmetricKey = ecsByte.([]byte)
	}

	//check header
	token, err := ecthttp.DecryptECTMHeader(httpRequest.Header, symmetricKey)
	if err != nil {
		return &ecthttp.ECTRequest{Rq: httpRequest, Token: nil, SymmetricKey: symmetricKey, DecryptedBody: nil, Err: err}
	}

	bodybyte, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		return &ecthttp.ECTRequest{Rq: httpRequest, Token: token, SymmetricKey: symmetricKey, DecryptedBody: nil, Err: errors.New("body error")}
	}

	decryptBody, err := ecthttp.DecryptBody(bodybyte, symmetricKey)
	if err != nil {
		return &ecthttp.ECTRequest{Rq: httpRequest, Token: token, SymmetricKey: symmetricKey, DecryptedBody: nil, Err: errors.New("decrypt error")}
	}

	return &ecthttp.ECTRequest{Rq: httpRequest, Token: token, SymmetricKey: symmetricKey, DecryptedBody: decryptBody, Err: nil}

}

func (hs *EctHttpServer) HandleGet(httpRequest *http.Request) *ecthttp.ECTRequest { // (symmetricKey []byte, token []byte, e error) {

	ecs, exist := httpRequest.Header["Ectm_key"]
	if !exist || len(ecs) < 1 || ecs[0] == "" {
		return &ecthttp.ECTRequest{Rq: httpRequest, Token: nil, SymmetricKey: nil, DecryptedBody: nil, Err: errors.New("ecs not exist")}
	}

	var symmetricKey []byte
	//try to get from cache
	ecsBase64Str := ecs[0]
	ecsByte, _, exist := hs.Cache.Get(ecsBase64Str)
	if !exist {
		ct, err := base64.StdEncoding.DecodeString(ecsBase64Str)
		if err != nil {
			return &ecthttp.ECTRequest{Rq: httpRequest, Token: nil, SymmetricKey: nil, DecryptedBody: nil, Err: err}
		}
		symmetricKey, err = utils.ECCDecrypt(hs.PrivateKey, ct)
		if err != nil {
			return &ecthttp.ECTRequest{Rq: httpRequest, Token: nil, SymmetricKey: nil, DecryptedBody: nil, Err: errors.New("ecs decrypt error")}
		}
		hs.Cache.Set(ecsBase64Str, symmetricKey, 3600)
	} else {
		symmetricKey = ecsByte.([]byte)
	}

	//check header
	token, err := ecthttp.DecryptECTMHeader(httpRequest.Header, symmetricKey)
	if err != nil {
		return &ecthttp.ECTRequest{Rq: httpRequest, Token: nil, SymmetricKey: symmetricKey, DecryptedBody: nil, Err: err}
	}

	return &ecthttp.ECTRequest{Rq: httpRequest, Token: token, SymmetricKey: symmetricKey, DecryptedBody: nil, Err: nil}

}

func ECTSendBack(header http.Header, symmetricKey []byte, data interface{}) ([]byte, error) {

	err := ecthttp.EncryptAndSetECTMHeader(header, nil, symmetricKey, nil)
	if err != nil {
		return nil, errors.New("encrypt response header error")
	}

	//body encrypt
	var EncryptedBody []byte
	var toEncrypt []byte

	if data == nil {
		toEncrypt = nil
		EncryptedBody = nil
	} else {
		switch data.(type) {
		case string:
			toEncrypt = []byte(data.(string))
		case []byte:
			toEncrypt = data.([]byte)
		default:
			toEncrypt, err = json.Marshal(data)
			if err != nil {
				return nil, errors.New("encrypt response data error")
			}
		}
		EncryptedBody, err = ecthttp.EncryptBody(toEncrypt, symmetricKey)
		if err != nil {
			return nil, errors.New("encrypt response data error")
		}
	}
	return EncryptedBody, nil
}
