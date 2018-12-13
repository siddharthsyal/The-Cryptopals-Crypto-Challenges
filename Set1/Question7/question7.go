package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
)

func decrypt(cipherText, key []byte) ([]byte){
	plainText := make([]byte, len(cipherText))
	cipherBlock,err := aes.NewCipher(key)
	if err !=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	for i:=16;i<=len(cipherText);i=i+16{
		cipherBlock.Decrypt(plainText[i-16:i],cipherText[i-16:i])
	}
	return plainText
}

func main(){
	key := "YELLOW SUBMARINE"
	filename := "question7_data.txt"
	filecontent, err := ioutil.ReadFile(filename)
	if err!=nil{
		fmt.Println("File Error")
		os.Exit(1)
	}
	cipherText,_:=base64.StdEncoding.DecodeString(string(filecontent))
	if len(cipherText)%16!=0{
		fmt.Println("File Size Error")
		os.Exit(1)
	}
	fmt.Println(string(decrypt(cipherText,[]byte(key))))
}
