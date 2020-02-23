package main

import (
	SRP "../pkg"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
)

func sendKeyMaterial(w http.ResponseWriter, r *http.Request){
	clientPubKey := new(big.Int)
	serverData := make(map[string]string)
	clientData := make(map[string]string)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&clientData)
	if err != nil{
		fmt.Println("JSON decoder error")
		os.Exit(1)
	}
	r.Body.Close()
	clientPubKey.SetString(clientData["PubKey"],10)
	serverData["Salt"]= string(SRP.Salt_Server)
	serverData["B"] = SRP.B_Server.String()
	rawBytes,error := json.Marshal(serverData)
	if error!=nil{
		fmt.Println("JSON response error")
		os.Exit(1)
	}
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(rawBytes)
	SRP.GenerateSessionKey_Server(clientPubKey)
	fmt.Println("Server: Salt & B sent to the client")
	fmt.Println("Server: Session key generated")
	return
}

func hmacVerification(w http.ResponseWriter, r *http.Request){
	clientData := make(map[string]string)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&clientData)
	if err != nil{
		fmt.Println("JSON decoder error")
		os.Exit(1)
	}
	r.Body.Close()
	fmt.Println("Server: HMAC verification request received")
	if SRP.VerifyHMAC([]byte(clientData["HMAC"])){
		w.WriteHeader(200)
	}else{
		w.WriteHeader(http.StatusForbidden)
		w.Write(nil)
		fmt.Println("Server: HMAC cannot be verified")
	}
}

func main(){
	router := http.NewServeMux()
	server := &http.Server{Addr:"127.0.0.1:5051",Handler:router}
	router.HandleFunc("/parameters",sendKeyMaterial)
	router.HandleFunc("/verify", hmacVerification)
	log.Fatal(server.ListenAndServe())
}