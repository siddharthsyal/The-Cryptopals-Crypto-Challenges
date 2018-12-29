package main

import (
	"crypto/aes"
	"fmt"
	"math"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"
)

var blockSize = 16
var key = initKey()

func initKey()[]byte{
	rand.Seed(time.Now().UnixNano())
	key := make([]byte,blockSize)
	_,err := rand.Read(key)
	if err !=nil{
		fmt.Println("Key Issue")
		os.Exit(1)
	}
	return key
}

func removePadding(plaintext_padded []byte)[]byte{
	paddingBytes := plaintext_padded[len(plaintext_padded)-1]
	plainText := make([]byte,len(plaintext_padded)-int(paddingBytes))
	copy(plainText,plaintext_padded[:len(plaintext_padded)-int(paddingBytes)])
	return plainText
}

func paddingPKCS7(plainText []byte) []byte{
	padding :=blockSize - int(math.Mod(float64(len(plainText)),float64(blockSize)))
	for i:= 0;i<padding;i++{
		plainText= append(plainText,byte(padding))
	}
	return plainText
}

func aesECBdnc(cipherText[]byte)[]byte{
	if len(cipherText)%blockSize !=0{
		fmt.Println("Padding Error")
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	plainText_padded := make([]byte,len(cipherText))
	for i:=0;i<len(cipherText);i=i+blockSize{
		cipherBlock.Decrypt(plainText_padded [i:i+blockSize],cipherText[i:i+blockSize])
	}
	return removePadding(plainText_padded )
}

func aesECBenc(plaintext[]byte)[]byte{
	if len(plaintext)%blockSize !=0{
		fmt.Println("Padding Error")
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	cipherText := make([]byte,len(plaintext))
	for i:=0;i<len(plaintext);i=i+blockSize{
		cipherBlock.Encrypt(cipherText[i:i+blockSize],plaintext[i:i+blockSize])
	}
	return cipherText
}

func profileFor(email string) []byte{
	v:= url.Values{}
	v.Add("email",email)
	fmt.Println(v.Encode())
	return []byte(v.Encode()+"&uid=10"+"&role=user")
}

func metaCharCheck(email string) bool{

	if strings.ContainsAny(email,"&")||strings.Contains(email,"="){
		return false
	}
	return true
}

func getChoosenCipherText()[]byte{
	plainText := "&role=admin"
	cipherText_padded := paddingPKCS7([]byte(plainText))
	cipherText := aesECBenc(cipherText_padded)
	return cipherText
}
func cutAndPaste(org_cipherText []byte)[]byte{
	new_cipherText := make([]byte,3*blockSize)
	copy(new_cipherText[:32],org_cipherText[0:32])
	copy(new_cipherText[32:],getChoosenCipherText())
	return new_cipherText
}

func main(){
	email := "random@random.com"
	if !metaCharCheck(email){
		fmt.Println("Check for meta characters")
		os.Exit(1)
	}
	profile_encode := profileFor(email)
	cipherText := aesECBenc(paddingPKCS7(profile_encode))
	fmt.Println("Original CipherText : ",string(cipherText))
	plainText := aesECBdnc(cipherText)
	fmt.Println("Original Decryption : ",string(plainText))
	new_CipherText := cutAndPaste(cipherText)
	fmt.Println("New CipherText : ",string(new_CipherText))
	new_plainText := aesECBdnc(new_CipherText)
	fmt.Print("New PlainText : ",string(new_plainText))
}