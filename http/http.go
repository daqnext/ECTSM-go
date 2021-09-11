package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/daqnext/ECTSM-go/utils"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

func GenECTHeader(token string, ecsKey string, symmetricKey []byte) (http.Header, error) {
	header := make(http.Header)
	if token != "" {
		header.Set("Authorization", token)
	}

	//sign
	if ecsKey != "" {
		header.Set("Ecs", ecsKey)
	}

	//time stamp
	err := SetECTResponseTimestamp(header, symmetricKey)
	if err != nil {
		return header, err
	}

	return header, nil
}

func SetECTResponseTimestamp(header http.Header, symmetricKey []byte) error {
	nowTime := time.Now().Unix()
	encrypted, err := utils.AESEncrypt(utils.Int64ToBytes(nowTime), symmetricKey)
	if err != nil {
		return err
	}
	timeStamp := base64.StdEncoding.EncodeToString(encrypted)
	header.Set("Ecttimestamp", timeStamp)
	return nil
}

func DecryptTimestamp(header http.Header, symmetricKey []byte) (timeStamp int64, e error) {
	//timeStamp
	timeS, exist := header["Ecttimestamp"]
	if !exist {
		e = errors.New("timestamp not exist")
		return 0, e
	}
	if len(timeS) < 1 || timeS[0] == "" {
		e = errors.New("timestamp error")
		return 0, e
	}
	timeStampBase64Str := timeS[0]
	timeByte, err := base64.StdEncoding.DecodeString(timeStampBase64Str)
	if err != nil {
		e = errors.New("timestamp error")
		return 0, e
	}
	timeB, err := utils.AESDecrypt(timeByte, symmetricKey)
	if err != nil {
		e = errors.New("decrypt timestamp error")
		return 0, e
	}
	timeStamp = utils.BytesToInt64(timeB)
	return timeStamp, nil
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
