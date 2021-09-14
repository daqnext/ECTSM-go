package http

import (
	"encoding/base64"
	"encoding/json"
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

func GenECTHeader(token string, ecsKey string, symmetricKey []byte) (http.Header, error) {
	header := make(http.Header)
	if token != "" {
		header.Set("Authorization", token)
	}

	if ecsKey != "" {
		header.Set("ecs", ecsKey)
	}

	//time stamp
	err := setECTTimestamp(header, symmetricKey)
	if err != nil {
		return header, err
	}

	return header, nil
}

func ECTResponse(header http.Header, data interface{}, symmetricKey []byte) (string, error) {
	//set response header timestamp
	err := setECTTimestamp(header, symmetricKey)
	if err != nil {
		return "", errors.New("encrypt response header error")
	}

	if data != nil {
		//response data encrypt
		sendData, err := EncryptBody(data, symmetricKey)
		if err != nil {
			return "", errors.New("encrypt response data error")
		}
		return base64.StdEncoding.EncodeToString(sendData), nil
	}
	return "", nil
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
