package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"
)

var blockSize = 16
var key = initKeyIV()

func initKeyIV()([]byte){
	rand.Seed(time.Now().UnixNano())
	key := make([]byte,blockSize)
	_,err := rand.Read(key)
	if err !=nil{
		fmt.Println("Key Issue")
		os.Exit(1)
	}
	return key
}


func validPadding(plainText_padded []byte)bool{
	padding := int(plainText_padded[len(plainText_padded)-1])
	if padding>16||padding<1{
		return false
	}
	for  i:= len(plainText_padded)-1;i>=len(plainText_padded)-padding;i--{
		if plainText_padded[i]!=byte(padding){
			return false
		}
	}
	return true
}

func xorBytes(a,b[]byte)[]byte{
	result := make ([]byte,16)
	for i,_ := range a{
		result[i] = a[i]^b[i]
	}
	return result
}

func paddingPKCS7(plainText []byte ) []byte{
	padding :=blockSize - int(math.Mod(float64(len(plainText)),float64(blockSize)))
	for i:= 0;i<padding;i++{
		plainText= append(plainText,byte(padding))
	}
	return plainText
}


func aesCBC_encrypt(plaintext_base64 []byte )[]byte{
	plaintext_unpadded := make([]byte,base64.StdEncoding.DecodedLen(len(plaintext_base64)))
	base64.StdEncoding.Decode(plaintext_unpadded,plaintext_base64)
	plaintext := paddingPKCS7(plaintext_unpadded)
	if len(plaintext)%blockSize != 0{
		fmt.Println("Padding Error")
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err !=nil{
		fmt.Println("Cipher Block Error")
		os.Exit(1)
	}
	cipherText := make([]byte,len(plaintext))
	IV := make([]byte,blockSize)
	_,err = rand.Read(IV)
	if err !=nil{
		fmt.Println("IV Issue")
		os.Exit(1)
	}
	for i:=0;i<=len(plaintext)-blockSize;i=i+blockSize{
		if i==0{
			buffer := xorBytes(plaintext[i:i+blockSize],IV)
			cipherBlock.Encrypt(cipherText[i:i+blockSize],buffer)
		}else if i!=0{
			buffer := xorBytes(plaintext[i:i+blockSize],cipherText[i-blockSize:i])
			cipherBlock.Encrypt(cipherText[i:i+blockSize],buffer)
		}
	}

	return append(IV,cipherText...)
}
func removePadding(plaintext_padded []byte)[]byte{
	paddingBytes := plaintext_padded[len(plaintext_padded)-1]
	return plaintext_padded[:len(plaintext_padded)-int(paddingBytes)]
}

func aesCBC_decrypt(cipherTextwithIV  []byte)bool{
	cipherText := make([]byte,len(cipherTextwithIV)-blockSize)
	copy(cipherText,cipherTextwithIV[16:len(cipherTextwithIV)])
	IV := make([]byte,blockSize)
	copy(IV,cipherTextwithIV[0:16])
	if len(cipherText)%blockSize != 0{
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err !=nil{
		fmt.Println("Cipher Block Error")
		os.Exit(1)
	}

	plainText_padded := make([]byte,len(cipherText))
	for i:=0;i<=len(cipherText)-16;i=i+blockSize{
		buffer := make([]byte,blockSize)
		if i==0{
			cipherBlock.Decrypt(buffer,cipherText[i:i+blockSize])
			temp := xorBytes(IV,buffer)
			copy(plainText_padded[i:i+blockSize] ,temp )
		}else if i!=0{
			cipherBlock.Decrypt(buffer,cipherText[i:i+blockSize])
			temp := xorBytes(cipherText[i-blockSize:i],buffer)
			copy(plainText_padded[i:i+blockSize] , temp)
		}
	}
	return validPadding(plainText_padded)
}

func readRandomLine()([]byte){
	sample := []string{"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=","MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}
	number := rand.Intn(10)
	return []byte(sample[number])
}


func paddingOracleAttack(orginalCipherText, target[]byte)[]byte{
	plainText := make([]byte,blockSize)
	prior_cipherText :=  make([]byte,blockSize)
	copy(prior_cipherText,orginalCipherText)
	I2 := make([]byte,blockSize)
	for pos := blockSize-1;pos>=0;pos--{
		pad_val :=blockSize-pos
		for j:= blockSize-1;j>pos;j--{
			prior_cipherText[j]=byte(pad_val)^I2[j]
		}
		for k:=0;k<=255;k++{
			prior_cipherText[pos] = byte(k)
			buffer := append(prior_cipherText,target...)
			if aesCBC_decrypt(buffer)==true{
				break
			}
		}
		I2[pos]= prior_cipherText[pos]^byte(pad_val)
		plainText[pos]= I2[pos]^orginalCipherText[pos]
	}
	return plainText
}


func paddingOracle(cipherText []byte)[]byte{
	plainText := make([]byte,len(cipherText)-blockSize)
	for i:=len(cipherText)-blockSize;i>=blockSize;i=i-blockSize{
		buffer:=paddingOracleAttack(cipherText[i-blockSize:i],cipherText[i:i+blockSize])
		copy(plainText[i-blockSize:i],buffer)
	}
	return plainText
}

func main(){
	plainText_base64 := readRandomLine()
	ciphertext := aesCBC_encrypt(plainText_base64)
	fmt.Println("Ciphertext = ",string(ciphertext))
	plainText := paddingOracle(ciphertext)
	fmt.Println("Plaintext = ",string(removePadding(plainText)))
}