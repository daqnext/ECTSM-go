package http

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/daqnext/ECTSM-go/utils"
)

const AllowRequestTimeGapSec = 180
const AllowServerClientTimeGap = 30

func EncryptAndSetECTMHeader(header http.Header, EcsKey []byte, symmetricKey []byte, token []byte) error {
	//set the ecs key only for request to server
	if len(EcsKey) != 0 {
		header.Set("ectm_key", base64.StdEncoding.EncodeToString(EcsKey))
	}
	//set the time
	nowTimeStr := strconv.FormatInt(time.Now().Unix(), 10)
	encrypted_time_byte, err := utils.AESEncrypt([]byte(nowTimeStr), symmetricKey)
	if err != nil {
		return err
	}
	header.Set("ectm_time", base64.StdEncoding.EncodeToString(encrypted_time_byte))
	//set token
	if len(token) != 0 {
		encrypted_token_byte, err := utils.AESEncrypt(token, symmetricKey)
		if err != nil {
			return err
		}
		header.Set("ectm_token", base64.StdEncoding.EncodeToString(encrypted_token_byte))
	}
	return nil
}

//can be called from both server side and client side
func DecryptECTMHeader(header http.Header, symmetricKey []byte) (token []byte, e error) {

	/////check time //////////
	timeS, exist := header["Ectm_time"]
	if !exist || len(timeS) < 1 || timeS[0] == "" {
		return nil, errors.New("timestamp not exist")
	}

	timeByte, err := base64.StdEncoding.DecodeString(timeS[0])
	if err != nil {
		return nil, errors.New("timestamp base64 format error")
	}

	timeDecrypted, err := utils.AESDecrypt(timeByte, symmetricKey)
	if err != nil {
		return nil, errors.New("decrypt timestamp error")
	}
	timeStamp, err := strconv.ParseInt(string(timeDecrypted), 10, 64)
	if err != nil {
		return nil, errors.New("timestamp ParseInt error")
	}
	timeGap := time.Now().Unix() - timeStamp
	if timeGap < -AllowRequestTimeGapSec || timeGap > AllowRequestTimeGapSec {
		return nil, errors.New("time Gap error")
	}

	///check token [optional]
	tokenS, exist := header["Ectm_token"]
	if exist && len(tokenS) > 0 && tokenS[0] != "" {
		tokenByte, err := base64.StdEncoding.DecodeString(tokenS[0])
		if err != nil {
			return nil, errors.New("token base64 format error")
		}
		tokenDecrypted, err := utils.AESDecrypt(tokenByte, symmetricKey)
		if err != nil {
			return nil, errors.New("decrypt token error")
		}
		return tokenDecrypted, nil
	}

	return nil, nil
}

func EncryptBody(dataByte []byte, randKey []byte) (EncryptedBody []byte, err error) {
	encryptedByte, err := utils.AESEncrypt(dataByte, randKey)
	if err != nil {
		return nil, err
	}
	return encryptedByte, nil
}

func DecryptBody(body []byte, randKey []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	bufDecrypted, err := utils.AESDecrypt(body, randKey)
	if err != nil {
		return nil, err
	}
	return bufDecrypted, nil
}

func ECTResponse(header http.Header, symmetricKey []byte, data []byte) ([]byte, error) {

	err := EncryptAndSetECTMHeader(header, nil, symmetricKey, nil)
	if err != nil {
		return nil, errors.New("encrypt response header error")
	}
	//body encrypt
	encryptedBody, err := EncryptBody(data, symmetricKey)
	if err != nil {
		return nil, errors.New("encrypt response data error")
	}
	return encryptedBody, nil
}
