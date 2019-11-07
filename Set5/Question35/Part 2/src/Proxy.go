package main

import(
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"../pkg/DHE"
	"../pkg/Enc"
)
var proxyEncKey []byte
/*************************G=P*******************/

/*Sends public key, generator and public exponent to the server*/
func parametersToServer(data map[string]string)(*http.Response){
	rawBytes, err := json.Marshal(data)
	if err !=nil{
		fmt.Println("JSON error")
	}
	ServerResponse, err :=http.Post("http://127.0.0.1:5052/parameters","application/json",bytes.NewBuffer(rawBytes))
	if err!=nil{
		fmt.Println("HTTP Post error")
		os.Exit(1)
	}
	fmt.Println("Proxy : DHE parameters sent to the server")
	return ServerResponse
}

/*Receives public key, generator and public exponent from the client*/
func parametersFromClient(w http.ResponseWriter, r *http.Request){
	var publicExp,g big.Int
	var message map[string]string
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&message)
	if err !=nil{
		fmt.Println("Decoder Error")
		os.Exit(1)
	}
	r.Body.Close()
	if r.Method == "POST"{
		fmt.Println("Proxy : Client DHE parameters received")
	}
	publicExp.SetString(message["PubExp"],10)// Public key for key generation by proxy
	g.SetString(message["G"],10)// Group generator for DHE
	serverResponse :=parametersToServer(message)//Sending the client parameters to the server
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(http.StatusOK)
	io.Copy(w,serverResponse.Body)//Sending the server response back to the client
	serverResponse.Body.Close()
	fmt.Println("Proxy : Sent the server public key to the client")
	proxyEncKey = DHE.GenerateSymmetricKey(&g,big.NewInt(10),&publicExp)//Key Generation
	return
}

/*Ending Application data to the server and returning the server response*/
func dataToServer(data map[string][]byte)(*http.Response){
	rawBytes, err := json.Marshal(data)
	if err !=nil{
		fmt.Println("JSON error")
	}
	response, err := http.Post("http://127.0.0.1:5052/data","application/json",bytes.NewBuffer(rawBytes))
	if err!=nil{
		fmt.Println("HTTP Post error")
		os.Exit(1)
	}
	fmt.Println("Proxy : DHE data sent to the server")
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
	r.Body.Close()
	fmt.Println("Proxy : Session data received from the client")
	serverResponse=dataToServer(payload)//Replaying the client data to the server and getting the server response
	plainText := Enc.GetPlainText(payload["data"],proxyEncKey)
	fmt.Println("Proxy: Plaintext of client message = ",string(plainText))
	decoder = json.NewDecoder(serverResponse.Body)
	err = decoder.Decode(&payload)
	if err!=nil{
		fmt.Println("JSON decode error")
		os.Exit(1)
	}
	serverResponse.Body.Close()
	plainText = Enc.GetPlainText(payload["data"],proxyEncKey)
	fmt.Println("Proxy: Plaintext of server message = ",string(plainText))
	rawBytes, err := json.Marshal(payload)
	if err !=nil{
		fmt.Println("JSON error")
	}
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(rawBytes)
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