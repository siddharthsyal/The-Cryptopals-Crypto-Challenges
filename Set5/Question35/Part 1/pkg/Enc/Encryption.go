package Enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func HexDecode(data []byte)[]byte{
	result := make([]byte, hex.DecodedLen(len(data)))
	hex.Decode(result,data)
	return result
}

func HexEncode(data []byte)[]byte{
	result := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(result,data)
	return result
}

func addPKCS7(data []byte)[]byte{
	padding := aes.BlockSize-(len(data)%aes.BlockSize)
	if padding != 0{
		for i:=0;i<padding;i++{
			data = append(data,byte(padding))
		}
		return data
	}else{
		result := make([]byte,len(data)+aes.BlockSize)
		copy(result,data)
		for i:=0;i<aes.BlockSize;i++{
			result = append(result,byte(aes.BlockSize))
		}
		return result
	}
}

func removePKCS7(data []byte)[]byte{
	padding := data[len(data)-1]
	result := make([]byte, len(data)-int(padding))
	copy(result,data[:len(data)-int(padding)])
	return result
}

func GetCipherText(data,key []byte)[]byte{
	iv := make([]byte, aes.BlockSize)
	input := addPKCS7(data)
	cipherText := make([]byte, aes.BlockSize+len(input))
	if len(input)%aes.BlockSize!=0{
		fmt.Println("Enc: Padding Error")
		os.Exit(98)
	}
	_, err := rand.Read(iv)
	if err!=nil{
		fmt.Println("IV error")
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	copy(cipherText[:aes.BlockSize],iv)
	mode := cipher.NewCBCEncrypter(cipherBlock,iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:],input)
	return HexEncode(cipherText)
}

func GetPlainText(data_hex,key []byte)[]byte{
	data := HexDecode(data_hex)
	if len(data)%aes.BlockSize!=0{
		fmt.Println("Dnc: Padding Error")
		os.Exit(98)
	}
	plainText_padded := make([]byte,len(data)-aes.BlockSize)
	iv := make([]byte, aes.BlockSize)
	copy(iv,data[:aes.BlockSize])
	block,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	mode := cipher.NewCBCDecrypter(block,iv)
	mode.CryptBlocks(plainText_padded,data[aes.BlockSize:])
	plainText := removePKCS7(plainText_padded)
	return plainText
}
