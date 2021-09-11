package client

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	ecthttp "github.com/daqnext/ECTSM-go/http"
	"github.com/daqnext/ECTSM-go/utils"
	"github.com/imroc/req"
	"math/rand"
	"time"
)

type EctHttpClient struct {
	PublicKeyUrl string
	SymmetricKey []byte
	PublicKeyEc  *ecdsa.PublicKey
	EcsKey       string
	Token        string
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
	//todo how to handle delay
	if timeGap < -30 || timeGap > 30 {
		return nil, errors.New("time error")
	}

	//pubKey
	pubKey, err := utils.StrBase64ToPublicKey(responseData.PublicKey)
	if err != nil {
		return nil, err
	}
	hc.PublicKeyEc = pubKey

	//randKey
	hc.SymmetricKey = []byte(utils.GenRandomKey())
	encrypted, err := utils.ECCEncrypt(hc.PublicKeyEc, hc.SymmetricKey)
	if err != nil {
		return nil, err
	}
	hc.EcsKey = base64.StdEncoding.EncodeToString(encrypted)

	return hc, nil
}

func (hc *EctHttpClient) SetUserToken(token string) {
	if token != "" {
		hc.Token = token
	}
}

func (hc *EctHttpClient) ECTGet(url string, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	return hc.ECTGetWithConfig(url, &RequestConfig{TimeoutSec: 30}, v)
}

func (hc *EctHttpClient) ECTGetWithConfig(url string, config *RequestConfig, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	//header
	header, err := ecthttp.GenECTHeader(hc.Token, hc.EcsKey, hc.SymmetricKey)
	if err != nil {
		return nil, nil, err
	}

	r := req.New()
	if config != nil && config.TimeoutSec > 0 {
		r.SetTimeout(time.Duration(config.TimeoutSec) * time.Second)
	}

	if config != nil && config.Token != "" {
		header["Authorization"] = config.Token
	}

	rs, err := r.Get(url, header, v)
	if err != nil {
		return nil, nil, err
	}
	if rs.Response().StatusCode != 200 {
		return rs, nil, nil
	}

	data, err := utils.AESDecrypt(rs.Bytes(), hc.SymmetricKey)
	if err != nil {
		return rs, nil, errors.New("decrypt error")
	}
	return rs, data, nil
}

func (hc *EctHttpClient) ECTPost(url string, obj interface{}, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	return hc.ECTPostWithConfig(url, &RequestConfig{TimeoutSec: 30}, obj, v)
}

func (hc *EctHttpClient) ECTPostWithConfig(url string, config *RequestConfig, obj interface{}, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	//header
	header, err := ecthttp.GenECTHeader(hc.Token, hc.EcsKey, hc.SymmetricKey)
	if err != nil {
		return nil, nil, err
	}

	r := req.New()
	if config != nil && config.TimeoutSec > 0 {
		r.SetTimeout(time.Duration(config.TimeoutSec) * time.Second)
	}

	if config != nil && config.Token != "" {
		header["Authorization"] = config.Token
	}

	bodySend, err := ecthttp.EncryptBody(obj, hc.SymmetricKey)
	if err != nil {
		return nil, nil, err
	}

	rs, err := r.Post(url, header, bodySend, v)
	if err != nil {
		return nil, nil, err
	}

	if rs.Response().StatusCode != 200 {
		return rs, nil, nil
	}

	data, err := ecthttp.DecryptBody(rs.Response().Body, hc.SymmetricKey)
	if err != nil {
		return rs, nil, errors.New("decrypt error")
	}
	return rs, data, nil
}