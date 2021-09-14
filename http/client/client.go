package client

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"math/rand"
	"time"

	ecthttp "github.com/daqnext/ECTSM-go/http"
	"github.com/daqnext/ECTSM-go/utils"
	"github.com/imroc/req"
)

type EctHttpClient struct {
	PublicKeyUrl string
	SymmetricKey []byte
	PublicKeyEc  *ecdsa.PublicKey
	EcsKey       string
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
	hc.SymmetricKey = []byte(utils.GenRandomKey())
	encrypted, err := utils.ECCEncrypt(hc.PublicKeyEc, hc.SymmetricKey)
	if err != nil {
		return nil, err
	}
	hc.EcsKey = base64.StdEncoding.EncodeToString(encrypted)

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
	header, err := ecthttp.GenECTHeader(config.Token, hc.EcsKey, hc.SymmetricKey)
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

	//check response timestamp
	timeStamp, err := ecthttp.DecryptTimestamp(rs.Response().Header, hc.SymmetricKey)
	if err != nil {
		return rs, nil, err
	}
	nowTime := time.Now().Unix()
	gap := nowTime - timeStamp
	if gap < -ecthttp.AllowRequestTimeGapSec || gap > ecthttp.AllowRequestTimeGapSec {
		return rs, nil, errors.New("timestamp error, timeout")
	}

	//decrypt response body
	data, err := ecthttp.DecryptBody(rs.Response().Body, hc.SymmetricKey)
	if err != nil {
		return rs, nil, errors.New("decrypt error")
	}
	return rs, data, nil
}

func (hc *EctHttpClient) ECTPost(url string, obj interface{}, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	return hc.ECTPostWithConfig(url, &RequestConfig{TimeoutSec: 30, Token: ""}, obj, v)
}

func (hc *EctHttpClient) ECTPostWithToken(url string, userToken string, obj interface{}, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	return hc.ECTPostWithConfig(url, &RequestConfig{TimeoutSec: 30, Token: userToken}, obj, v)
}

func (hc *EctHttpClient) ECTPostWithConfig(url string, config *RequestConfig, obj interface{}, v ...interface{}) (reqResp *req.Resp, decryptBody []byte, err error) {
	//header
	header, err := ecthttp.GenECTHeader(config.Token, hc.EcsKey, hc.SymmetricKey)
	if err != nil {
		return nil, nil, err
	}

	r := req.New()
	if config != nil && config.TimeoutSec > 0 {
		r.SetTimeout(time.Duration(config.TimeoutSec) * time.Second)
	}

	bodySend, err := ecthttp.EncryptBody(obj, hc.SymmetricKey)
	if err != nil {
		return nil, nil, err
	}

	bodySendStr := base64.StdEncoding.EncodeToString(bodySend)
	rs, err := r.Post(url, header, bodySendStr, req.Header{
		"Content-Type": "text/plain",
	}, v)
	if err != nil {
		return nil, nil, err
	}

	if rs.Response().StatusCode != 200 {
		return rs, nil, nil
	}

	//check response timestamp
	timeStamp, err := ecthttp.DecryptTimestamp(rs.Response().Header, hc.SymmetricKey)
	if err != nil {
		return rs, nil, err
	}
	nowTime := time.Now().Unix()
	gap := nowTime - timeStamp
	if gap < -ecthttp.AllowRequestTimeGapSec || gap > ecthttp.AllowRequestTimeGapSec {
		return rs, nil, errors.New("timestamp error, timeout")
	}

	//decrypt response body
	data, err := ecthttp.DecryptBody(rs.Response().Body, hc.SymmetricKey)
	if err != nil {
		return rs, nil, errors.New("decrypt error")
	}
	return rs, data, nil
}
