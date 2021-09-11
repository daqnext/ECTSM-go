package example

import (
	"log"
	"net/http"
	"testing"
	"time"

	ecthttp "github.com/daqnext/ECTSM-go/http"
	"github.com/daqnext/ECTSM-go/http/server"
	"github.com/daqnext/ECTSM-go/utils"
	"github.com/labstack/echo/v4"
)

var privateKeyBase64Str = "bhbb4EC96zx2uUsWDtSYivzaZUzdeDKMfn+dSV9VwUI="
var publicKeyBase64Str = "BJJlxQFcPuVTjaB/PvbqmN0py98C2iScUQlvpRUm+kpAgqJmnofCely42Hczgb7cqwTZtFTfPwm2ImdmDtvFMH4="

var hs *server.EctHttpServer

func Test_GenKeyPair(t *testing.T) {
	GenKeyPair()
}

func Test_StartHttpServer(t *testing.T) {
	StartHttpServer()
}

func GenKeyPair() {
	utils.GenAndPrintEccKeyPair()
}

func StartHttpServer() {
	var err error
	hs, err = server.New(privateKeyBase64Str)
	if err != nil {
		log.Fatal(err)
	}

	e := echo.New()
	// add middleware and routes
	// ...
	e.GET("/ectminfo", handlerEctminfo)
	e.GET("/test/get", handlerGetTest)
	e.POST("/test/post", handlerPostTest)

	go func() {
		if err := e.Start(":8080"); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	time.Sleep(1 * time.Hour)
}

func handlerEctminfo(c echo.Context) error {
	type publicKeyResponse struct {
		UnixTime  int64
		PublicKey string
	}
	r := &publicKeyResponse{
		UnixTime:  time.Now().Unix(),
		PublicKey: publicKeyBase64Str,
	}
	c.JSON(200, r)
	return nil
}

func handlerGetTest(c echo.Context) error {
	//check header
	symmetricKey, timeStamp, err := hs.CheckHeader(c.Request().Header)
	if err != nil {
		c.String(500, "decrypt header error")
	}

	//do something
	//...
	log.Println(string(symmetricKey))
	log.Println(timeStamp)

	//responseData example
	type responseData struct {
		Status int
		Msg    string
		Data   interface{}
	}
	data := &responseData{
		Status: 0,
		Msg:    "post success",
		Data:   nil,
	}

	//response data encrypt
	sendData, err := ecthttp.EncryptBody(data, symmetricKey)
	if err != nil {
		c.String(500, "encrypt response data error")
		return nil
	}
	c.JSONBlob(200, sendData)
	return nil
}

func handlerPostTest(c echo.Context) error {

	symmetricKey, timeStamp, decryptedBody, err := hs.HandlePost(c.Request().Header, c.Request().Body)
	if err != nil {
		c.String(500, "decrypt header error:")
	}

	//print result
	log.Println(string(symmetricKey))
	log.Println(timeStamp)
	log.Println(string(decryptedBody))

	//responseData example
	type responseData struct {
		Status int
		Msg    string
		Data   interface{}
	}
	data := &responseData{
		Status: 0,
		Msg:    "post success",
		Data:   nil,
	}

	sendData, err := ecthttp.EncryptBody(data, symmetricKey)
	if err != nil {
		c.String(500, "encrypt response data error")
		return nil
	}

	c.JSONBlob(200, sendData)
	return nil
}
