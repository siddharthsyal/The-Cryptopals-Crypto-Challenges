package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

func detectECB (cipherText []byte) bool{
	tracker := make(map[string]int)
	init := false
	for i:=16;i<=len(cipherText);i++{
		if !init{
			tracker[string(cipherText[i-16:i])]=1
			init = true
		}else{
			if _,ok := tracker[string(cipherText[i-16:i])];ok==true{
				return ok
			}else{
				tracker[string(cipherText[i-16:i])]=1
			}
		}
	}
	return false
}
func HexDecode(input []byte)([]byte){
	cipherText := make([]byte,hex.DecodedLen(len(input)))
	hex.Decode(cipherText,input)
	return cipherText
}
func main(){
	filename := "question8_data.txt"
	filecontent,err := ioutil.ReadFile(filename)
	if err!=nil{
		fmt.Println("File Read Error")
		os.Exit(1)
	}
	filecontent_byte := bytes.Split(filecontent,[]byte("\n"))
	for _,cipherText_hex := range filecontent_byte{
		cipherText_unhex := HexDecode([]byte(cipherText_hex))
		if detectECB(cipherText_unhex)==true{
			fmt.Println(string(cipherText_hex))
			return
		}

	}
}
