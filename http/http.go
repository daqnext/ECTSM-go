package http

import (
	"encoding/base64"
	"encoding/json"
	"github.com/daqnext/ECTSM-go/utils"
	"github.com/imroc/req"
	"io"
	"io/ioutil"
	"time"
)

func GenECTHeader(token string, ecsKey string, symmetricKey []byte) (req.Header, error) {
	header := req.Header{}
	if token != "" {
		header["Authorization"] = token
	}

	//sign
	if ecsKey != "" {
		header["Ecs"] = ecsKey
	}

	//time stamp
	nowTime := time.Now().Unix()
	encrypted, err := utils.AESEncrypt(utils.Int64ToBytes(nowTime), symmetricKey)
	if err != nil {
		return header, err
	}
	timeStamp := base64.StdEncoding.EncodeToString(encrypted)
	header["Timestamp"] = timeStamp

	return header, nil
}

func DecryptBody(body io.ReadCloser, randKey []byte) ([]byte, error) {
	buf, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, err
	}

	//decrypt
	bufDecrypted, err := utils.AESDecrypt(buf, randKey)
	if err != nil {
		return nil, err
	}
	//str:=base64.StdEncoding.EncodeToString(bufDecrypted)
	return bufDecrypted, nil
}

func EncryptBody(data interface{}, randKey []byte) ([]byte, error) {
	dataByte, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	sendData, err := utils.AESEncrypt(dataByte, randKey)
	if err != nil {
		return nil, err
	}
	return sendData, nil
}
