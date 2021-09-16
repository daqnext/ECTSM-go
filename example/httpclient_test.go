package example

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/daqnext/ECTSM-go/http/client"
)

func Test_json(t *testing.T) {
	result, _ := json.Marshal(1.5)
	log.Println(string(result))
}

func Test_request(t *testing.T) {
	HttpRequest()
}

func HttpRequest() {
	//new ecthttpclient instance as a global single instance
	//publicKeyUrl endpoint to get unix time and public key form server
	hc, err := client.New("http://127.0.0.1:8080/ectminfo")
	if err != nil {
		log.Fatal(err)
	}

	//get
	{
		url := "http://127.0.0.1:8080/test/get"
		//send request with default timeout and token 'usertoken'
		r, responseData, err := hc.ECTGetWithToken(url, "usertoken")
		//or use hc.ECTGetWithConfig() for custom config

		if err != nil {
			log.Println(err)
			return
		}
		log.Println("status", r.Response().StatusCode)
		log.Println("get request reponse", string(responseData))
	}

	//post
	{
		//struct for example
		sendData := struct {
			Name  string
			Email string
			Phone string
			Age   int
		}{"Jack", "jack@gmail.com", "123456789", 19}
		dataByte, _ := json.Marshal(&sendData)
		r, responseData, err := hc.ECTPostWithToken("http://127.0.0.1:8080/test/post", "userToken", dataByte)
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("status", r.Response().StatusCode)
		log.Println("get request reponse", string(responseData))
	}
}
