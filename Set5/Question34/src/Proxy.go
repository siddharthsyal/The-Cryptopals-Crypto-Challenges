package main

import(
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"../pkg/DHE"
	"../pkg/Enc"
)
var proxyEncKey []byte

/*Sends public key, generator and public exponent to the server*/
func parametersToServer(data map[string]string){
	rawBytes, err := json.Marshal(data)
	if err !=nil{
		fmt.Println("JSON error")
	}
	_, err =http.Post("http://127.0.0.1:5052/parameters","application/json",bytes.NewBuffer(rawBytes))
	if err!=nil{
		fmt.Println("HTTP Post error")
		os.Exit(1)
	}
	fmt.Println("Proxy : DHE parameters sent to the server")
	return
}

/*Receives public key, generator and public exponent from the server*/
func parametersFromClient(w http.ResponseWriter, r *http.Request){
	var publicKey big.Int
	var message map[string]string
	serverData := make(map[string]string)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&message)
	if err !=nil{
		fmt.Println("Decoder Error")
		os.Exit(1)
	}
	if r.Method == "POST"{
		fmt.Println("Proxy : Client DHE parameters received")
	}
	message["PubKey"]=message["PubExp"]//Parameter injection
	publicKey.SetString(message["PubExp"],10)// Public key for key generation by proxy
	parametersToServer(message)//Sending the modified data to the server
	r.Body.Close()
	serverData["ServerPub"] = message["PubExp"]//Sending client the public exponent as the public key of the server.
	rawBytes,error := json.Marshal(serverData)
	if error!=nil{
		fmt.Println("JSON response error")
		os.Exit(1)
	}
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(rawBytes)
	fmt.Println("Proxy : Sent back the server public key to the client")
	proxyEncKey = DHE.GenerateSymmetricKey(&publicKey,big.NewInt(10),&publicKey)//Key Generation
	return
}

/*Ending Application data to the server and returning the server response*/
func dataToServer(data map[string][]byte)(*http.Response){
	var response *http.Response
	rawBytes, err := json.Marshal(data)
	if err !=nil{
		fmt.Println("JSON error")
	}
	response, err =http.Post("http://127.0.0.1:5052/data","application/json",bytes.NewBuffer(rawBytes))
	if err!=nil{
		fmt.Println("HTTP Post error")
		os.Exit(1)
	}
	fmt.Println("Proxy : DHE parameters sent to the server")
	return response
}

/*Application data received from the client*/
func dataFromClient(w http.ResponseWriter, r *http.Request){
	var serverResponse *http.Response
	payload := make(map[string][]byte)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&payload)
	if err!=nil{
		fmt.Println("JSON decode error")
		os.Exit(1)
	}
	fmt.Println("Proxy : Session data received from the client")
	cipherText := payload["data"]
	plainText := Enc.GetPlainText(cipherText,proxyEncKey)
	fmt.Println("Proxy: Plaintext of client message = ",string(plainText))
	serverResponse=dataToServer(payload)//Replaying the client data to the server and getting the server response
	decoder = json.NewDecoder(serverResponse.Body)
	err = decoder.Decode(&payload)
	cipherText = payload["data"]
	plainText = Enc.GetPlainText(cipherText,proxyEncKey)
	fmt.Println("Proxy: Plaintext of server message = ",string(plainText))
	r.Body.Close()
	rawBytes,error := json.Marshal(payload)
	if error!=nil{
		fmt.Println("JSON response error")
		os.Exit(1)
	}
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(rawBytes)//Sending the server response to the client
	return
}

func main(){
	http.HandleFunc("/parameters",parametersFromClient)
	http.HandleFunc("/data",dataFromClient)
	err :=http.ListenAndServe("127.0.0.1:5051",nil)
	if err!=nil{
		fmt.Println("Cannot start the server")
		os.Exit(1)
	}
}