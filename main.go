package main

import (
	"encoding/base64"
	"fmt"

	"github.com/daqnext/ECTSM-go/utils"
)

func main() {

	//////// first  part /////////////////////////

	prikey_gen, _ := utils.GenSecp256k1KeyPair()
	prikey_gen_string := utils.PrivateKeyToString(prikey_gen)
	pubkey_gen_string := utils.PublicKeyToString(&prikey_gen.PublicKey)
	fmt.Println("privatekey generated:", prikey_gen_string)
	fmt.Println("publickey generated:", pubkey_gen_string)

	//////// second part /////////////////////////

	///////encrypt by public key//////////
	rawMsg := "hello world"
	pubKeyStr := "BMveUrioxvhfjsJ+WqkwXRwpgm+NPwEOFlXPAkhW4+HrI7kMEuklEJjolFQjSBLYDQ76e050fQjybfvAofHtf8M="
	pubkeyfromstring, _ := utils.StrBase64ToPublicKey(pubKeyStr)
	encryptmsg, _ := utils.ECCEncrypt(pubkeyfromstring, []byte(rawMsg))
	base64msg := base64.StdEncoding.EncodeToString(encryptmsg)
	fmt.Println("encryptmsg to base64:", base64msg)

	////////decrypt by private key//////////
	prikey_string := "To6r0h//zNLAvl/NuS3KPmUhURJOJCt4hOb8K+/7R3s="
	prikeyfromstring, _ := utils.StrBase64ToPrivateKey(prikey_string)
	encryptmsgfrombase64, _ := base64.StdEncoding.DecodeString(base64msg)
	decryptmsg, _ := utils.ECCDecrypt(prikeyfromstring, encryptmsgfrombase64)
	fmt.Println("decrypted raw msg :", string(decryptmsg))

}
