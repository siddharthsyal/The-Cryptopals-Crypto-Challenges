package main

import(
	"fmt"
	"math"
)
var blockSize = 16

func validPadding(plainText_padded []byte)bool{
	padding := int(plainText_padded[len(plainText_padded)-1])
	messageLen := len(plainText_padded)-padding
	rfcPadding := blockSize - int((math.Mod(float64(messageLen),float64(blockSize))))
	for  i:= len(plainText_padded)-rfcPadding;i<len(plainText_padded);i++{
		if plainText_padded[i]!=byte(rfcPadding){
			return false
		}
	}
	return true
}

func stripPadding (plainText_padded []byte)[]byte{
	paddingLen := int(plainText_padded[len(plainText_padded)-1])
	plainText := make([]byte, len(plainText_padded)-paddingLen)
	copy(plainText,plainText_padded[:len(plainText_padded)-paddingLen])
	return plainText
}

func main(){
	plainText_padded :=  []byte("ICE ICE BABY\x04\x04\x04\x04")
	if validPadding(plainText_padded){
		fmt.Println("Valid Padding")
		fmt.Println("PlainText = ",string(stripPadding(plainText_padded)))
	}else{
		fmt.Println("Invalid Padding")
	}
}