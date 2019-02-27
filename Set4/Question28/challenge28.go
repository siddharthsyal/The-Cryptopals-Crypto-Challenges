package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

func verifySHA1(sha1_calulated ,plainText string)bool{
	h := sha1.New()
	io.WriteString(h,plainText)
	if len(sha1_calulated)!=len(hex.EncodeToString(h.Sum(nil))){
		return false
	}
	if strings.Compare(sha1_calulated,hex.EncodeToString(h.Sum(nil)))!=0{
		return false
	}
	return true
}

func tamperMAC(old_digest string ,message []byte){
	new_digest := Sha1(string(message))
	if verifySHA1(new_digest,string(message)){
		if old_digest!=new_digest{
			fmt.Println("Cannot break without the secret key")
		}else{
			fmt.Println("MAC broken without key")
		}
	}
}

func main(){
	userInput := "This is a test for hash function"
	key :="of2tCeQw"
	digest := Sha1(key + userInput)
	if verifySHA1(digest,key+userInput){
		fmt.Println("SHA1 Calculation Successful")
	}else{
		fmt.Println("Wrong SHA1 value")
	}
	tamperMAC(digest,[]byte(userInput))
}