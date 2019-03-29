package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)
var key = initKey()
var flag bool = false
func initKey()[]byte{
	b := make([]byte,10)
	_,err := rand.Read(b)
	if err!= nil{
		fmt.Println("Key Error")
		os.Exit(1)
	}
	return b
}
func getSignature(filename string)[]byte{
	return hmac([]byte(filename),key)
}

func verifySignature(filename ,signature_user string)bool{
	signature_new := getSignature(filename)
	signature,_ := hex.DecodeString(signature_user)
	for i:=0;i<len(signature_new)&&i<len(signature);i++{
		if signature[i]!=signature_new[i]{
			return false
		}
		time.Sleep(20*time.Millisecond)
	}
	return true
}

func handleRequest(w http.ResponseWriter, r *http.Request){
	query := r.URL.Query()
	if _,ok := query["filename"];ok==false{
		io.WriteString(w,string("Zero"))
		return
	}
	if _,ok := query["signature"]; ok==false{//Signature not present
		filename,_:=query["filename"]
		new_signature := getSignature(filename[0])
		io.WriteString(w,string(new_signature))
		return
	}
	signature,_:=query["signature"]
	filename_user:= query["filename"]
	if verifySignature(filename_user[0],signature[0])==true{
		io.WriteString(w,"true")
	}else{
		io.WriteString(w,"false")
	}
	return
}

func main(){
	mux := http.NewServeMux()
	mux.HandleFunc("/",handleRequest)
	err := http.ListenAndServe("127.0.0.1:80", mux)
	if err !=nil{
		fmt.Println("HTTP Server issue")
		os.Exit(1)
	}else{
		fmt.Println("Server Initialized Successfully")
	}
}