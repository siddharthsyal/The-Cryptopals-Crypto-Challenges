package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)
var flag bool = false

func sendGetRequest(filename,signature string)bool{
	client := http.Client{}
	resp,err := client.Get("http://127.0.0.1/?filename="+filename+"&signature="+signature)
	if err!=nil{
		fmt.Println(err)
		os.Exit(1)
	}
	body,err := ioutil.ReadAll(resp.Body)
	if strings.Compare(string(body),"false")==0{
		return false
	}else{
		return true
	}
}
func attackSucess(filename string, signature []byte)bool{
	if sendGetRequest(filename,hex.EncodeToString(signature))==false{
		return false
	}
	return true
}

func main(){
	filename:= "Siddharth"
	signature := make([]byte,sha1.Size)//Size = 20
	sucess_time:=0.0
	for i:=0;i<sha1.Size;i++{
		expected_time := float64(i+1)*0.95*sucess_time
		for j:=0;j<=255;j++{
			signature[i]=byte(j)
			t2 := time.Now()
			sendGetRequest(filename,hex.EncodeToString(signature))
			duration := time.Since(t2)
			if sucess_time ==0.0{
				if (duration.Seconds()>0.018&&duration.Seconds()<0.023){
					sucess_time = duration.Seconds()
					break
				}
			}else{
				if (duration.Seconds()>expected_time){
					break
				}
				if j==255{
					fmt.Println("Attack Fails")
					os.Exit(98)
				}
			}
		}

		fmt.Println("Progress = ",((i+1)*100)/20, "%")
	}
	if attackSucess(filename,signature){
		fmt.Println("HMAC Forged")
	}else{
		fmt.Println("Bad Attack")
	}
}