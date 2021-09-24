package client

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	ecthttp "github.com/daqnext/ECTSM-go/http"
	"github.com/daqnext/ECTSM-go/utils"
	"github.com/imroc/req"
)

type EctHttpClient struct {
	PublicKeyUrl string
	SymmetricKey []byte
	EcsKey       []byte
	PublicKeyEc  *ecdsa.PublicKey
}

const DefaultTimeout = 30

func New(publicKeyUrl string) (*EctHttpClient, error) {
	rand.Seed(time.Now().UnixNano())
	hc := &EctHttpClient{
		PublicKeyUrl: publicKeyUrl,
	}

	r := req.New()
	r.SetTimeout(time.Second * 15)
	response, err := r.Do("GET", publicKeyUrl)
	if err != nil {
		return nil, err
	}
	type publicKeyResponse struct {
		UnixTime  int64
		PublicKey string
	}
	var responseData publicKeyResponse
	err = response.ToJSON(&responseData)
	if err != nil {
		return nil, err
	}

	//time
	nowTime := time.Now().Unix()
	timeGap := nowTime - responseData.UnixTime
	if timeGap < -ecthttp.AllowServerClientTimeGap || timeGap > ecthttp.AllowServerClientTimeGap {
		return nil, errors.New("time error")
	}
	//pubKey
	pubKey, err := utils.StrBase64ToPublicKey(responseData.PublicKey)
	if err != nil {
		return nil, err
	}
	hc.PublicKeyEc = pubKey

	//randKey
	hc.SymmetricKey = utils.GenSymmetricKey()
	hc.EcsKey, err = utils.ECCEncrypt(hc.PublicKeyEc, hc.SymmetricKey)
	if err != nil {
		return nil, err
	}
	return hc, nil
}

func (hc *EctHttpClient) ECTGet(url string, Token []byte, v ...interface{}) *ecthttp.ECTResponse {
	//header
	header := make(http.Header)
	err := ecthttp.EncryptAndSetECTMHeader(header, hc.EcsKey, hc.SymmetricKey, Token)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: nil, DecryptedBody: nil, Err: err}
	}

	r := req.New()
	r.SetTimeout(time.Duration(DefaultTimeout) * time.Second)

	rs, err := r.Get(url, header, v)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: nil, DecryptedBody: nil, Err: err}
	}

	body, err := ioutil.ReadAll(rs.Response().Body)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: nil, Err: errors.New("body error")}
	}

	if rs.Response().StatusCode != 200 {
		errStr := fmt.Sprintf("response status error,status code:%d,content:%s", rs.Response().StatusCode, string(body))
		return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: nil, Err: errors.New(errStr)}
	}

	_, err = ecthttp.DecryptECTMHeader(rs.Response().Header, hc.SymmetricKey)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: nil, Err: err}
	}

	//decrypt response body
	decryptBody, err := ecthttp.DecryptBody(body, hc.SymmetricKey)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: nil, Err: errors.New("body decrypt error")}
	}

	return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: decryptBody, Err: nil}
}

func (hc *EctHttpClient) ECTPost(url string, Token []byte, data interface{}, v ...interface{}) *ecthttp.ECTResponse {

	//header
	header := make(http.Header)
	err := ecthttp.EncryptAndSetECTMHeader(header, hc.EcsKey, hc.SymmetricKey, Token)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: nil, DecryptedBody: nil, Err: err}
	}

	//set request timeout
	r := req.New()
	r.SetTimeout(time.Duration(DefaultTimeout) * time.Second)

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
				return &ecthttp.ECTResponse{Rs: nil, DecryptedBody: nil, Err: err}
			}
		}
		EncryptedBody, err = ecthttp.EncryptBody(toEncrypt, hc.SymmetricKey)
		if err != nil {
			return &ecthttp.ECTResponse{Rs: nil, DecryptedBody: nil, Err: err}
		}
	}

	rs, err := r.Post(url, header, EncryptedBody, req.Header{
		"Content-Type": "text/plain",
	}, v)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: nil, DecryptedBody: nil, Err: err}
	}

	body, err := ioutil.ReadAll(rs.Response().Body)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: nil, Err: errors.New("body error")}
	}

	if rs.Response().StatusCode != 200 {
		errStr := fmt.Sprintf("response status error,status code:%d,content:%s", rs.Response().StatusCode, string(body))
		return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: nil, Err: errors.New(errStr)}
	}

	_, err = ecthttp.DecryptECTMHeader(rs.Response().Header, hc.SymmetricKey)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: nil, Err: err}
	}

	//decrypt response body
	decryptBody, err := ecthttp.DecryptBody(body, hc.SymmetricKey)
	if err != nil {
		return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: nil, Err: errors.New("decrypt error")}
	}

	return &ecthttp.ECTResponse{Rs: rs.Response(), DecryptedBody: decryptBody, Err: nil}
}
