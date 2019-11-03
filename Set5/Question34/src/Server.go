package main

import(
	"../pkg/DHE"
	"../pkg/Enc"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
)

var sessionKeyServer []byte

func Serverparameters(w http.ResponseWriter, r *http.Request){
	var P, G , client_pub big.Int
	var message map[string]string
	serverData := make(map[string]string)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&message)
	if err !=nil{
		fmt.Println("Decoder Error")
		os.Exit(1)
	}
	if r.Method == "POST"{
		fmt.Println("Server : Client DHE parameters received")
	}
	P.SetString(message["PubExp"],10)
	G.SetString(message["G"],10)
	client_pub.SetString(message["PubKey"],10)
	serverPub := DHE.GetServerPublicKey(&P,&G)
	serverData["ServerPub"] = serverPub
	r.Body.Close()
	rawBytes,error := json.Marshal(serverData)
	if error!=nil{
		fmt.Println("JSON response error")
		os.Exit(1)
	}
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(rawBytes)
	getEncKeyServer(&client_pub,&P)
	return
}

func getEncKeyServer(clientPub,p *big.Int){
	sessionKeyServer = DHE.GetServerKey(clientPub,p)
	fmt.Println("Server : Session key generated")
}

func ServerdataStream(w http.ResponseWriter, r *http.Request) {
	appData := make(map[string][]byte)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&appData)
	if err!=nil{
		fmt.Println("JSON decode error")
		os.Exit(1)
	}
	fmt.Println("Server : Session data received from the client")
	cipherText := appData["data"]
	plainText := Enc.GetPlainText(cipherText,sessionKeyServer)
	if string(plainText)=="Military Grade Encryption"{
		fmt.Println("Server : Session data decryption successful")
		respData := make(map[string][]byte)
		respData["Data"]=Enc.GetCipherText(plainText,sessionKeyServer)
		rawBytes, err := json.Marshal(respData)
		if err!=nil{
			fmt.Println("JSON response error")
			os.Exit(1)
		}
		w.Header().Set("Content-Type","application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(rawBytes)
		fmt.Println("Server : Successful DHE")
	}else {
		w.WriteHeader(http.StatusBadRequest)
	}
}


func main(){
	http.HandleFunc("/parameters",Serverparameters)
	http.HandleFunc("/data",ServerdataStream)
	err :=http.ListenAndServe("127.0.0.1:5052",nil)
	if err!=nil{
		fmt.Println("Cannot start the server")
		os.Exit(1)
	}
}