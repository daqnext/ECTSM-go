package example

import (
	"encoding/json"
	"fmt"
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
		result := hc.ECTGet(url, []byte("usertoken"))
		if result.Err != nil {
			fmt.Println(result.Err)
		} else {
			fmt.Println("result:", result.ToString())
		}
	}

	//post
	{
		sendData := struct {
			Name  string
			Email string
			Phone string
			Age   int
		}{"Jack", "jack@gmail.com", "123456789", 19}
		result := hc.ECTPost("http://127.0.0.1:8080/test/post", []byte("userToken"), sendData)
		if result.Err != nil {
			fmt.Println(result.Err)
		} else {
			fmt.Println("result:", result.ToJson().GetContentAsString())
		}
	}
}
