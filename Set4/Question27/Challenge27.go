package main

import(
	"bytes"
	"crypto/aes"
	"fmt"
	"math"
	"math/rand"
	"os"
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
	return key,key
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

func aesCBC_decrypt(cipherText  []byte)([]byte,bool){
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
	return plainText,checkHighASCII(plainText)
}

func checkHighASCII(plaintext []byte)bool{
	for _,val :=range  plaintext{
		if int(val)>127{
			return true
		}
	}
	return false
}
func attacker(cipherText []byte)[]byte{
	cipherText_modified := make([]byte,len(cipherText))
	copy(cipherText_modified,cipherText)
	for i:=16;i<32;i++{
		cipherText_modified[i]=0
	}
	copy(cipherText_modified[32:48],cipherText_modified[0:16])
	return cipherText_modified
}
func recoverKey(cipherText_modified []byte)[]byte{
	plaintext,err:= aesCBC_decrypt(cipherText_modified)
	if err{
		fmt.Println("High ASCII")
	}
	recoveredKey := xorBytes(plaintext[0:16],plaintext[32:48])
	return recoveredKey

}

func main(){
	userdata := []byte("Ehrsam, Meyer, Smith and Tuchman invented the Cipher Block Chaining (CBC) mode of operation")
	cipherText := aesCBC_encrypt(userdata)
	cipherText_modified := attacker(cipherText)
	recoveredKey := recoverKey(cipherText_modified)
	if bytes.Equal(recoveredKey,IV){
		fmt.Println("Key Recovered")
		fmt.Println("Recovered Key = ",recoveredKey,"\nActual Key = ",key)
	}else{
		fmt.Println("Key Not Recovered")
		fmt.Println("Recovered Key = ",recoveredKey,"\nActual Key = ",key)
	}
}