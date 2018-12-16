package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
)

func xorBytes(a,b[]byte)[]byte{
	result := make ([]byte,16)
	for i,_ := range a{
		result[i] = a[i]^b[i]
	}
	return result
}

func cbcDecrypt(ciphertext,key[]byte)([]byte){
	plaintext := make([]byte,len(ciphertext))
	buffer := make([]byte,16)
	iv := make([]byte,16)
	iv = []byte("0")
	blocksize := 16
	init := true
	cipherblock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("Cipher Block Error")
		os.Exit(1)
	}
	for i:= blocksize;i<=len(ciphertext);i=i+blocksize{
		if init{
			cipherblock.Decrypt(buffer,ciphertext[i-blocksize:i])
			copy(plaintext[i-blocksize:i],xorBytes(iv,buffer))
			init = false
		}else if init == false{
			cipherblock.Decrypt(buffer,ciphertext[i-blocksize:i])
			copy(plaintext[i-blocksize:i],xorBytes(ciphertext[i-(2*blocksize):i-blocksize],buffer[:]))
		}
	}
	return plaintext
}

func main(){
	filename := "challenge2_file.txt"
	filecontent,err := ioutil.ReadFile(filename)
	if err!= nil{
		fmt.Println("File Error")
		os.Exit(1)
	}
	key := []byte("YELLOW SUBMARINE")
	ciphertext,_ := base64.StdEncoding.DecodeString(string(filecontent))
	fmt.Println(string(cbcDecrypt(ciphertext,key)))
}