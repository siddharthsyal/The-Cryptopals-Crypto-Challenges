package main

import (
	"../pkg/DHE"
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"../pkg/Enc"
)

var sessionKeyClient []byte

func Clientparameters()(*http.Response,string){
	pubKey, p_string,g_string := DHE.GetClientPublicKey()
	message := make(map[string]string)
	message["PubKey"]=pubKey
	message["G"]=g_string
	message["PubExp"]=p_string
	rawBytes, err := json.Marshal(message)
	if err !=nil{
		fmt.Println("JSON error")
	}
	resp, err :=http.Post("http://127.0.0.1:5051/parameters","application/json",bytes.NewBuffer(rawBytes))
	if err!=nil{
		fmt.Println("HTTP Post error")
		os.Exit(1)
	}
	fmt.Println("Client : DHE parameters sent to the server")
	return resp,p_string
}

func dataStream(serverResponse *http.Response, p_string string){
	data := make(map[string]string)
	decoder := json.NewDecoder(serverResponse.Body)
	err := decoder.Decode(&data)
	if err != nil{
		fmt.Println("JSON decoder error")
		os.Exit(1)
	}
	defer serverResponse.Body.Close()
	fmt.Println("Client : Server public key received")
	getEncKeyClient(data["ServerPub"],p_string)
}

func applicationData() (*http.Response){
	payload := make(map[string][]byte)
	cipherText := Enc.GetCipherText([]byte("Military Grade Encryption"),sessionKeyClient)
	payload["data"]=cipherText;
	rawBytes, error := json.Marshal(payload)
	if error !=nil{
		fmt.Println("JSON error")
		os.Exit(1)
	}
	resp, err :=http.Post("http://127.0.0.1:5051/data","application/json",bytes.NewBuffer(rawBytes))
	if err!=nil{
		fmt.Println("HTTP Post error")
		os.Exit(1)
	}
	fmt.Println("Client : Application data sent to the server")
	return resp
}


func getEncKeyClient(serverPub,p string){
	serverPubKey := new(big.Int)
	P := new(big.Int)
	serverPubKey.SetString(serverPub,10)
	P.SetString(p,10)
	sessionKeyClient = DHE.GetClientKey(serverPubKey,P)
}

func verifyDHE(resp *http.Response){
	data := make(map[string][]byte)
	decoder := json.NewDecoder(resp.Body)
	err := decoder.Decode(&data)
	if err != nil{
		fmt.Println("JSON decoder error")
		os.Exit(1)
	}
	if resp.StatusCode==http.StatusBadRequest{
		fmt.Println("Client : DHE Error")
		os.Exit(1)
	}
	plainText := Enc.GetPlainText(data["Data"],sessionKeyClient)
	if bytes.Equal(plainText,[]byte("Military Grade Encryption")){
		fmt.Println("Client : Successful DHE")
	}
	resp.Body.Close()
}


func main(){
	response, p_string:= Clientparameters()
	dataStream(response,p_string)
	response = applicationData()
	verifyDHE(response)
}