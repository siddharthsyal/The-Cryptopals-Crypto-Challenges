package main

import(
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"strings"
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

func prependData(plaintext []byte)[]byte{
	data := "comment1=cooking%20MCs;userdata="
	return []byte(data + string(plaintext))
}

func quoteOut(plainText []byte)[]byte{
	buffer := strings.Replace(string(plainText),";","?",-2)
	buffer=strings.Replace(buffer,"=","?",-2)
	return []byte(buffer)
}

func appendData(plaintext []byte)[]byte{
	data := ";comment2=%20like%20a%20pound%20of%20bacon"
	return []byte(string(plaintext)+data)
}

func getModifiedCipherText(cipherText []byte)[]byte{
	cipherText_block := make([]byte,blocksize)
	copy(cipherText_block,cipherText[32:48])
	cipherText_block[0] = cipherText_block[0]^byte(';')^byte('A')
	cipherText_block[11] = cipherText_block[11]^byte(';')^byte('A')
	cipherText_block[6] = cipherText_block[6]^byte('=')^byte('A')
	copy(cipherText[32:48],cipherText_block)
	return cipherText
}

func attackSucess(cipherText []byte)(bool,[]byte){
	cipherText_new := getModifiedCipherText(cipherText)
	plaintext_new := aesCTR_decrypt(cipherText_new)
	if strings.Contains(string(plaintext_new),";admin=true;"){
		return true,plaintext_new
	}
	return false,plaintext_new
}

func main(){
	userData := "AadminAtrueA"
	plaintext := prependData([]byte(userData))
	plaintext = appendData(plaintext)
	plaintext = quoteOut(plaintext)
	fmt.Println("Orginal Plaintext = ",string(plaintext))
	cipherText := aesCTR_encrypt(plaintext)
	flag,new_plaintext:=attackSucess(cipherText)
	if flag{
		fmt.Println("Attack Success")
		fmt.Println("New Plaintext = ",string(new_plaintext))
	}else{
		fmt.Println("Attack Fail")
	}
}