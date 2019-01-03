package main

import (
	"crypto/aes"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strings"
	"time"
)

var blockSize = 16
var key,IV = initKeyIV()

func initKeyIV()([]byte,[]byte){
	rand.Seed(time.Now().UnixNano())
	key := make([]byte,blockSize)
	_,err := rand.Read(key)
	if err !=nil{
		fmt.Println("Key Issue")
		os.Exit(1)
	}
	IV := make([]byte,blockSize)
	_,err = rand.Read(IV)
	if err !=nil{
		fmt.Println("Random Bytes Issue")
		os.Exit(1)
	}

	return key,IV
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

func removePadding(plaintext_padded []byte)[]byte{
	paddingBytes := plaintext_padded[len(plaintext_padded)-1]
	plainText := make([]byte,len(plaintext_padded)-int(paddingBytes))
	copy(plainText,plaintext_padded[:len(plaintext_padded)-int(paddingBytes)])
	return plainText
}

func aesCBC_encrypt(plaintext_unpadded []byte )[]byte{
	blockSize := 16
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

	for i:=0;i<len(plaintext);i=i+blockSize{
		if i==0{
			buffer := xorBytes(plaintext[i:i+blockSize],IV)
			cipherBlock.Encrypt(cipherText[i:i+blockSize],buffer)
		}else if i!=0{
			buffer := xorBytes(plaintext[i:i+blockSize],cipherText[i-blockSize:i])
			cipherBlock.Encrypt(cipherText[i:i+blockSize],buffer)
		}
	}
	return cipherText
}

func aesCBC_decrypt(cipherText  []byte)[]byte{
	blockSize := 16
	if len(cipherText)%blockSize != 0{
		fmt.Println("Padding Error")
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err !=nil{
		fmt.Println("Cipher Block Error")
		os.Exit(1)
	}
	plainText_padded := make([]byte,len(cipherText))
	for i:=0;i<len(cipherText);i=i+blockSize{
		buffer := make([]byte,blockSize)
		if i==0{
			cipherBlock.Decrypt(buffer,cipherText[i:i+blockSize])
			copy(plainText_padded[i:i+blockSize] , xorBytes(IV,buffer))
		}else if i!=0{
			cipherBlock.Decrypt(buffer,cipherText[i:i+blockSize])
			copy(plainText_padded[i:i+blockSize] , xorBytes(cipherText[i-blockSize:i],buffer))
		}
	}
	plainText := removePadding(plainText_padded)
	return plainText
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

func getModifiedCipherText(cipherText,plainText []byte)[]byte{
	before_xor_plaintext := xorBytes(plainText[32:48],cipherText[16:32])
	cipherText_block := make([]byte,blockSize)
	copy(cipherText_block,cipherText[16:32])
	cipherText_block[0] = before_xor_plaintext[0]^byte(';')
	cipherText_block[11] = before_xor_plaintext[11]^byte(';')
	cipherText_block[6] = before_xor_plaintext[6]^byte('=')
	copy(cipherText[16:32],cipherText_block)
	return cipherText
}

func attackSucess(cipherText []byte)bool{
	cipherText_new := getModifiedCipherText(cipherText,aesCBC_decrypt(cipherText))
	plaintext_new := aesCBC_decrypt(cipherText_new)
	if strings.Contains(string(plaintext_new),";admin=true;"){
		return true
	}
	return false
}

func main(){
	userData := ";admin=true;"
	plaintext := prependData([]byte(userData))
	plaintext = appendData(plaintext)
	plaintext = quoteOut(plaintext)
	fmt.Println(string(plaintext))
	cipherText := aesCBC_encrypt(plaintext)
	fmt.Println("CipherText ",string(cipherText))
	if attackSucess(cipherText){
		fmt.Println("Attack Success")
	}else{
		fmt.Println("Bad Attack")
	}
}