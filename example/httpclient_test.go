package example

import (
	"log"
	"testing"

	"github.com/daqnext/ECTSM-go/http/client"
)

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
	url := "http://127.0.0.1:8080/test/get"
	//send request with default timeout and token 'usertoken'
	r, responseData, err := hc.ECTGetWithToken(url, "usertoken")
	//or use hc.ECTGetWithConfig() for custom config
	//type RequestConfig struct {
	//	Token      string
	//	TimeoutSec int
	//}

	if err != nil {
		log.Println(err)
		return
	}
	log.Println("status", r.Response().StatusCode)
	log.Println("get request reponse", string(responseData))

	//post
	//struct for example
	type UserInfo struct {
		Name  string
		Email string
		Phone string
		Age   int
	}
	sendData := &UserInfo{
		Name:  "Jack",
		Email: "jack@gmail.com",
		Phone: "123456789",
		Age:   18,
	}

	url = "http://127.0.0.1:8080/test/post"
	r, responseData, err = hc.ECTPost(url, sendData)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("status", r.Response().StatusCode)
	log.Println("get request reponse", string(responseData))
}
