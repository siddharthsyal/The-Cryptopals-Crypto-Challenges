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

func getAverage(filename string,data []byte, iteration int) float64{
	avg_time :=0.0
	for i:=0;i<iteration;i++{
		t1:= time.Now()
		sendGetRequest(filename,hex.EncodeToString(data))
		duration := time.Since(t1)
		avg_time = avg_time+duration.Seconds()
	}
	return avg_time/float64(iteration)
}

func main(){
	filename:= "Siddharth"
	signature := make([]byte,sha1.Size)//Size = 20
	base_time := getAverage(filename,signature,100)
	fmt.Println("Base Time is ",base_time)
	success_time :=0.0
	for i:=1;i<=sha1.Size;i++{
		expected_time := float64(i)*(success_time-(base_time))
		if i!=1{
			fmt.Println("Expected Time for Byte i ",i," is ",expected_time)
		}
		max_avg_duration :=0.0
		var buffer byte
		for j:=0;j<=255;j++{
			signature[i-1]=byte(j)
			/*Adding sleep timer to prevent false positives*/
			time.Sleep(50*time.Millisecond)
			t1:= time.Now()
			sendGetRequest(filename,hex.EncodeToString(signature))
			duration := time.Since(t1)
			if duration.Seconds()>max_avg_duration{
				buffer_time := getAverage(filename,signature,20)
				time.Sleep(50*time.Millisecond)
				if max_avg_duration<buffer_time{
					max_avg_duration=buffer_time
					buffer = byte(j)
				}
			}
			if success_time==0.0{
				if duration.Seconds()>(base_time+(0.005*0.95)){
					runTime := getAverage(filename,signature,50)
					success_time=runTime
					break
				}
			}else if duration.Seconds()>expected_time{
				runTime := getAverage(filename,signature,50)
				if runTime>expected_time{
					success_time = ((runTime/float64(i))+success_time)/2
					break
				}else{
					fmt.Println("False Positive Alert for Byte ",i)
					continue
				}
			}
			if j==255&&max_avg_duration!=0.0{
				fmt.Println("Trying luck with max byte for byte ",i)
				runTime := getAverage(filename,signature,100)
				signature[i-1]=buffer
				success_time = ((runTime/float64(i))+success_time)/2
				break
			}else if j==255{
				fmt.Println("Error State")
				os.Exit(20)
			}
		}
		fmt.Println("Progress = ",((i)*100)/20, "%")
		}

	if attackSucess(filename,signature){
		fmt.Println("HMAC Forged")
	}else{
		fmt.Println("Bad Attack")
	}
	}
