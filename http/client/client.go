package client

import (
	"crypto/ecdsa"
	"errors"
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

type RequestConfig struct {
	Token      string
	TimeoutSec int
}

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

func (hc *EctHttpClient) ECTGet(url string, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	return hc.ECTGetWithConfig(url, &RequestConfig{TimeoutSec: 30, Token: ""}, v)
}

func (hc *EctHttpClient) ECTGetWithToken(url string, userToken string, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	return hc.ECTGetWithConfig(url, &RequestConfig{TimeoutSec: 30, Token: userToken}, v)
}

func (hc *EctHttpClient) ECTGetWithConfig(url string, config *RequestConfig, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	//header
	header := make(http.Header)
	err = ecthttp.EncryptAndSetECTMHeader(header, hc.EcsKey, hc.SymmetricKey, []byte(config.Token))
	if err != nil {
		return nil, nil, err
	}

	r := req.New()
	if config != nil && config.TimeoutSec > 0 {
		r.SetTimeout(time.Duration(config.TimeoutSec) * time.Second)
	}

	rs, err := r.Get(url, header, v)
	if err != nil {
		return nil, nil, err
	}
	if rs.Response().StatusCode != 200 {
		return rs, nil, nil
	}

	_, err = ecthttp.DecryptECTMHeader(rs.Response().Header, hc.SymmetricKey)
	if err != nil {
		return nil, nil, err
	}

	//decrypt response body
	body, err := ioutil.ReadAll(rs.Response().Body)
	if err != nil {
		return rs, nil, errors.New("body error")
	}
	decryptBody, err = ecthttp.DecryptBody(body, hc.SymmetricKey)
	if err != nil {
		return rs, nil, errors.New("body decrypt error")
	}
	return rs, decryptBody, nil
}

func (hc *EctHttpClient) ECTPost(url string, data []byte, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	return hc.ECTPostWithConfig(url, &RequestConfig{TimeoutSec: 30, Token: ""}, data, v)
}

func (hc *EctHttpClient) ECTPostWithToken(url string, userToken string, data []byte, v ...interface{}) (reqResp *req.Resp, decryptBodyStr []byte, err error) {
	return hc.ECTPostWithConfig(url, &RequestConfig{TimeoutSec: 30, Token: userToken}, data, v)
}

func (hc *EctHttpClient) ECTPostWithConfig(url string, config *RequestConfig, data []byte, v ...interface{}) (reqResp *req.Resp, decryptBodyStr []byte, err error) {
	//header
	header := make(http.Header)
	err = ecthttp.EncryptAndSetECTMHeader(header, hc.EcsKey, hc.SymmetricKey, []byte(config.Token))
	if err != nil {
		return nil, nil, err
	}

	//set request timeout
	r := req.New()
	if config != nil && config.TimeoutSec > 0 {
		r.SetTimeout(time.Duration(config.TimeoutSec) * time.Second)
	}

	EncryptedBody, err := ecthttp.EncryptBody(data, hc.SymmetricKey)
	if err != nil {
		return nil, nil, err
	}

	rs, err := r.Post(url, header, EncryptedBody, req.Header{
		"Content-Type": "text/plain",
	}, v)
	if err != nil {
		return nil, nil, err
	}

	if rs.Response().StatusCode != 200 {
		return rs, nil, nil
	}

	_, err = ecthttp.DecryptECTMHeader(rs.Response().Header, hc.SymmetricKey)
	if err != nil {
		return rs, nil, err
	}

	//decrypt response body
	body, err := ioutil.ReadAll(rs.Response().Body)
	if err != nil {
		return rs, nil, errors.New("body error")
	}

	decryptBody, err := ecthttp.DecryptBody(body, hc.SymmetricKey)
	if err != nil {
		return rs, nil, errors.New("decrypt error")
	}
	return rs, decryptBody, nil
}
