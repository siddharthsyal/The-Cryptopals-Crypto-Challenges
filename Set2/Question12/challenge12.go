package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math"
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

func aesECB(plaintext []byte)[]byte{
	if len(plaintext)%blocksize !=0{
		fmt.Println("Padding Error")
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	cipherText := make([]byte,len(plaintext))
	for i:=0;i<len(plaintext);i=i+blocksize{
		cipherBlock.Encrypt(cipherText[i:i+blocksize],plaintext[i:i+blocksize])
	}
	return cipherText
}

func paddingPKCS7(plainText []byte ) []byte{
	padding :=blocksize - int(math.Mod(float64(len(plainText)),float64(blocksize)))
	for i:= 0;i<padding;i++{
		plainText= append(plainText,byte(padding))
	}
	return plainText
}

func guessBlockSize(unknown string)int{
	plaintext := "A"
	length :=0
	init :=false
	var buffer string
	for {
		if !init{
			buffer = plaintext+unknown
			plaintext_padded := paddingPKCS7([]byte(buffer))
			cipherText := aesECB(plaintext_padded)
			length = len(cipherText)
			init = true
		}else if init{
			buffer = plaintext+buffer
			plaintext_padded := paddingPKCS7([]byte(buffer))
			cipherText := aesECB(plaintext_padded)
			length_new := len(cipherText)
			if length_new>length{
				return length_new-length
			}
		}
	}
	return length
}

func lookupTable(prefix []byte)map[string]byte{
	var i byte
	tracker := make(map[string]byte)
	for i=0;i<128;i++{
		buffer := append(prefix,i)
		buffer_padded :=paddingPKCS7(buffer)
		cipherText := aesECB(buffer_padded)
		tracker[string(cipherText[0:16])]=i
	}
	return tracker
}

func crackECB(unknownText []byte,blocksize int)[]byte{
	var plainText []byte
	for i:=blocksize;i<len(unknownText);i=i+blocksize{
		var decrypted []byte
		for j:=blocksize-1;j>=0;j--{
			prefix := bytes.Repeat([]byte("A"),j)
			prefix_new := append(prefix,decrypted...)
			lookup := lookupTable(prefix_new)
			buffer := append(prefix,unknownText[i-blocksize:i]...)
			plainText_padded := paddingPKCS7(buffer)
			cipherText := aesECB(plainText_padded)
			decrypted = append(decrypted,lookup[string(cipherText[0:blocksize])])
		}
		plainText = append(plainText,decrypted...)
	}
	return plainText
	}

func main(){
	unkownString_base64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	len := base64.StdEncoding.DecodedLen(len(unkownString_base64))
	unknownstring := make([]byte,len)
	_,err:=base64.StdEncoding.Decode(unknownstring,[]byte(unkownString_base64))
	if err != nil{
		fmt.Print("Unknown string encoding issue")
		os.Exit(1)
	}
	guessedBlockSize := guessBlockSize(string(unknownstring))
	plainText := crackECB(unknownstring,guessedBlockSize)
	fmt.Print("Plaintext = \n",string(plainText))
}