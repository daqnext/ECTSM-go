package example

import (
	"encoding/json"
	"log"
	"net/http"
	"testing"
	"time"

	ecthttp "github.com/daqnext/ECTSM-go/http"
	"github.com/daqnext/ECTSM-go/http/server"
	"github.com/daqnext/ECTSM-go/utils"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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

	//cors for html use
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		ExposeHeaders: []string{
			"ecttimestamp", "ecs",
			"Ecttimestamp", "Ecs",
			"Authorization", "authorization",
		},
	}))
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

	r := struct {
		UnixTime  int64
		PublicKey string
	}{time.Now().Unix(), publicKeyBase64Str}
	return c.JSON(200, &r)
}

func handlerGetTest(c echo.Context) error {
	//check header
	symmetricKey, token, err := hs.HandleGet(c.Request().Header)
	if err != nil {
		return c.String(500, "decrypt header error")
	}

	log.Println("symmetricKey", string(symmetricKey))
	log.Println("token", token)

	//responseData example
	data := struct {
		Status int
		Msg    string
		Data   interface{}
	}{0, "post success", nil}
	responseData, err := json.Marshal(&data)
	if err != nil {
		log.Println("err", err)
		return err
	}

	sendData, err := ecthttp.ECTResponse(c.Response().Header(), symmetricKey, responseData)
	if err != nil {
		return c.String(500, err.Error())
	}
	return c.String(200, string(sendData))
}

func handlerPostTest(c echo.Context) error {

	symmetricKey, token, decryptedBody, err := hs.HandlePost(c.Request().Header, c.Request().Body)
	if err != nil {
		return c.String(500, "decrypt header error:")
	}

	//print result
	log.Println("symmetricKey", string(symmetricKey))
	log.Println("token", token)
	log.Println("decryptedBody", string(decryptedBody))

	var requestBodyObj = struct {
		Name  string
		Email string
		Phone string
		Age   int
	}{}
	json.Unmarshal(decryptedBody, &requestBodyObj)
	log.Println(requestBodyObj)

	//responseData example
	data := struct {
		Status int
		Msg    string
		Data   interface{}
	}{0, "post success", nil}
	responseData, err := json.Marshal(&data)
	if err != nil {
		log.Println("err", err)
		return err
	}

	sendData, err := ecthttp.ECTResponse(c.Response().Header(), symmetricKey, responseData)
	if err != nil {
		return c.String(500, err.Error())
	}
	return c.String(200, string(sendData))
}
