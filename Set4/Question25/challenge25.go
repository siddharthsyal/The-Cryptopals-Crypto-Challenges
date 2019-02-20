package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"
)

var blocksize int
var key = initKey()

func initKey()[]byte{
	rand.Seed(time.Now().UnixNano())
	blocksize =16
	key := make([]byte,blocksize)
	_,err := rand.Read(key)
	if err !=nil{
		fmt.Println("Key Issue")
		os.Exit(1)
	}
	return key
}


func decrypt(cipherText, key []byte) ([]byte){
	plainText := make([]byte, len(cipherText))
	cipherBlock,err := aes.NewCipher(key)
	if err !=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	for i:=0;i<=len(cipherText)-16;i=i+16{
		cipherBlock.Decrypt(plainText[i:i+16],cipherText[i:i+16])
	}
	return plainText
}

func aesCTR_decrypt(cipherText []byte)[]byte{
	var plainText []byte
	tracker := 0
	i:=0
	cipherBlock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	var counter,nonce int64
	counter =0
	nonce =0
	nonce_byte := make([]byte,8)
	counter_byte := make([]byte,8)
	for len(plainText)<=len(cipherText){
		buffer := make([]byte,blocksize)
		binary.LittleEndian.PutUint64(nonce_byte, uint64(nonce))
		binary.LittleEndian.PutUint64(counter_byte, uint64(counter))
		cipherBlock.Encrypt(buffer,append(nonce_byte,counter_byte...))
		for i=0;i<16;i++{
			if tracker==len(cipherText){
				return plainText
			}
			plainText = append(plainText,buffer[i]^cipherText[tracker])
			tracker++
		}
		nonce =0
		counter++
	}
	return plainText
}

func aesCTR_encrypt(plainText []byte)[]byte{
	var cipherText []byte
	tracker := 0
	i:=0
	cipherBlock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	var counter,nonce int64
	counter =0
	nonce =0
	nonce_byte := make([]byte,8)
	counter_byte := make([]byte,8)
	for len(cipherText)<=len(plainText){
		buffer := make([]byte,blocksize)
		binary.LittleEndian.PutUint64(nonce_byte, uint64(nonce))
		binary.LittleEndian.PutUint64(counter_byte, uint64(counter))
		cipherBlock.Encrypt(buffer,append(nonce_byte,counter_byte...))
		for i=0;i<16;i++{
			if tracker==len(plainText){
				return cipherText
			}
			cipherText = append(cipherText,buffer[i]^plainText[tracker])
			tracker++
		}
		nonce =0
		counter++
	}
	return cipherText
}
func edit(cipherText []byte,newText byte, offset int)[]byte{
	plainText := aesCTR_decrypt(cipherText)
	plainText[offset]=newText
	cipherText_new:=aesCTR_encrypt(plainText)
	return cipherText_new
	}

func aesBruteforce(cipherText []byte)[]byte{
	plainText := make([]byte,len(cipherText))
	for i:=0;i<len(cipherText);i++{
		for j:=0;j<256;j++{
			newCipherText := edit(cipherText,byte(j),i)
			if newCipherText[i]==cipherText[i]{
				plainText = append(plainText,byte(j))
				break
			}
		}
	}
	return plainText
}

func main(){
	filename := "challenge25_text.txt"
	filecontent, err := ioutil.ReadFile(filename)
	if err !=nil{
		fmt.Println("Input File Error")
		os.Exit(1)
	}
	ciphertext,_ := base64.StdEncoding.DecodeString(string(filecontent))
	if len(ciphertext)%16!=0{
		fmt.Println("File Size Error")
		os.Exit(1)
	}
	plainText := decrypt(ciphertext,[]byte("YELLOW SUBMARINE"))
	cipherText_aesctr := aesCTR_encrypt(plainText)
	plainText_recovered := aesBruteforce(cipherText_aesctr)
	fmt.Println(string(plainText_recovered))
}