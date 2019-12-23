package main

import(
	client"../pkg"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func sendEmailAndPubKey()string{
	payload := make(map[string]string)
	payload["Email"]= client.Email
	payload["PubKey"] = client.ClientPub.String()
	rawBytes, err := json.Marshal(payload)
	if err != nil{
		fmt.Println("Client: JSON Marshal Error")
		os.Exit(1)
	}
	req, err :=http.NewRequest("POST","http://127.0.0.1:5051/parameters",bytes.NewBuffer(rawBytes))
	if err !=nil{
		fmt.Println("Client: Error generating the request")
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(req)
	if err!= nil{
		fmt.Println("HTTP request error")
		os.Exit(98)
	}
	fmt.Println("Client: Email & PublicKey sent to the server")
	return generateKey(response)
}

func generateKey(serverResponse *http.Response)string{
	data := make(map[string]string)
	decoder := json.NewDecoder(serverResponse.Body)
	err := decoder.Decode(&data)
	if err !=nil{
		fmt.Println("Client: JSON decoder error")
		os.Exit(1)
	}
	serverResponse.Body.Close()
	hmac := client.GenerateClientSessionKey(data["Salt"],data["B"])
	fmt.Println("Client: Session key generated")
	return hmac
}

func sendHMAC(hmac string){
	payload := make(map[string]string)
	payload["HMAC"] = hmac
	rawBytes, err := json.Marshal(payload)
	if err != nil{
		fmt.Println("Client: JSON Marshal Error")
		os.Exit(1)
	}
	req, err :=http.NewRequest("POST","http://127.0.0.1:5051/verify",bytes.NewBuffer(rawBytes))
	if err !=nil{
		fmt.Println("Client: Error generating the request")
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection","close")
	client := &http.Client{}
	response, err := client.Do(req)
	fmt.Println("Client: HMAC verification request sent")
	if err!= nil{
		fmt.Println("Client: HTTP request error")
		fmt.Println(err)
		os.Exit(98)
	}
	if (response.StatusCode==http.StatusOK){
		fmt.Println("Client: HMAC verification successful")
	}else{
		fmt.Println("Client: HMAC verification failed")
	}
	return
}

func main(){
	sendHMAC(sendEmailAndPubKey())
}