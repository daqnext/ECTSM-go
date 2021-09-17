package example

import (
	"fmt"
	"log"
	"net/http"
	"testing"
	"time"

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
			"Ectm_key", "ectm_key",
			"Ectm_time", "ectm_time",
			"Ectm_token", "ectm_token",
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
	ectRq := hs.HandleGet(c.Request())
	if ectRq.Err != nil {
		return c.String(500, "decrypt header error")
	}

	log.Println("symmetricKey", ectRq.GetSymmetricKey())
	log.Println("token", ectRq.GetToken())

	//responseData example
	data := struct {
		Status int
		Msg    string
		Data   interface{}
	}{0, "post success", nil}

	sendData, err := server.ECTSendBack(c.Response().Header(), ectRq.SymmetricKey, data)
	if err != nil {
		return c.String(500, err.Error())
	}
	return c.Blob(200, "application/octet-stream", sendData)
}

func handlerPostTest(c echo.Context) error {

	EctRq := hs.HandlePost(c.Request(), c.Request().Body)
	if EctRq.Err != nil {
		return c.String(500, "decrypt post error:")
	}

	//print result
	log.Println("symmetricKey", EctRq.GetSymmetricKey())
	log.Println("token", EctRq.GetToken())
	log.Println("decryptedBody", EctRq.ToString())

	jResult := EctRq.ToJson()
	name, err := jResult.GetString("Name")
	if err != nil {
		fmt.Println("Name:", name)
	}

	//responseData example
	data := struct {
		Status int
		Msg    string
		Data   interface{}
	}{0, "post success", nil}

	sendData, err := server.ECTSendBack(c.Response().Header(), EctRq.SymmetricKey, data)
	if err != nil {
		return c.String(500, err.Error())
	}
	return c.Blob(200, "application/octet-stream", sendData)
}
