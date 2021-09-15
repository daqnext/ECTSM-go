package http

import (
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/daqnext/ECTSM-go/utils"
)

const AllowRequestTimeGapSec = 180
const AllowServerClientTimeGap = 30

func GenECTHeader(ecsKey string, symmetricKey []byte, token string) (http.Header, error) {
	header := make(http.Header)

	if ecsKey == "" || symmetricKey == nil {
		return nil, errors.New("ecsKey && symmetricKey are both required ")
	}

	header.Set("ecs", ecsKey)
	err := setECTTimestamp(header, symmetricKey)
	if err != nil {
		return nil, err
	}

	if token != "" {
		header.Set("Authorization", token)
	}

	return header, nil
}

func ECTResponse(header http.Header, obj interface{}, symmetricKey []byte) (string, error) {
	//set response header timestamp
	err := setECTTimestamp(header, symmetricKey)
	if err != nil {
		return "", errors.New("encrypt response header error")
	}

	if obj == nil {
		return "", nil
	}

	dataByte, err := utils.InterfaceToByte(obj)
	if err != nil {
		return "", err
	}

	//response data encrypt
	sendStrBase64, err := EncryptBody(dataByte, symmetricKey)
	if err != nil {
		return "", errors.New("encrypt response data error")
	}
	return sendStrBase64, nil

}

func setECTTimestamp(header http.Header, symmetricKey []byte) error {
	nowTimeStr := strconv.FormatInt(time.Now().Unix(), 10)
	encrypted, err := utils.AESEncrypt([]byte(nowTimeStr), symmetricKey)
	if err != nil {
		return err
	}
	timeStamp := base64.StdEncoding.EncodeToString(encrypted)
	header.Set("ecttimestamp", timeStamp)
	return nil
}

func DecryptTimestamp(header http.Header, symmetricKey []byte) (timeStamp int64, e error) {
	//timeStamp
	timeS, exist := header["Ecttimestamp"]
	if !exist {
		return 0, errors.New("timestamp not exist")
	}
	if len(timeS) < 1 || timeS[0] == "" {
		return 0, errors.New("timestamp error")
	}
	timeStampBase64Str := timeS[0]
	timeByte, err := base64.StdEncoding.DecodeString(timeStampBase64Str)
	if err != nil {
		return 0, errors.New("timestamp error")
	}
	timeB, err := utils.AESDecrypt(timeByte, symmetricKey)
	if err != nil {
		return 0, errors.New("decrypt timestamp error")
	}
	timeStamp, err = strconv.ParseInt(string(timeB), 10, 64)
	if err != nil {
		return 0, errors.New("decrypt timestamp ParseInt error")
	}
	return timeStamp, nil
}

func DecryptBody(body io.ReadCloser, randKey []byte) ([]byte, error) {
	buf, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, nil
	}

	bodyBuf, err := base64.StdEncoding.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}
	//decrypt
	bufDecrypted, err := utils.AESDecrypt(bodyBuf, randKey)
	if err != nil {
		return nil, err
	}
	return bufDecrypted, nil
}

func EncryptBody(dataByte []byte, randKey []byte) (sendStrBase64 string, err error) {
	encryptByte, err := utils.AESEncrypt(dataByte, randKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptByte), nil
}
