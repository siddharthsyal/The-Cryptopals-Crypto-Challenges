package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

func xorCipher(text, key []byte)([]byte){
	i :=0
	result := make([]byte,len(text))
	for j,_ := range text{
		result[j] = text[j] ^ key[i]
		if (i) == len(key)-1{
			i=0
		}else{
			i++
		}
	}
	return result
}

func main(){
	filename := "question5_input.txt"
	text,err := ioutil.ReadFile(filename)
	if err != nil{
		fmt.Println("File Error")
		os.Exit(1)
	}
	key := "ICE"
	buffer := xorCipher([]byte(text),[]byte(key))
	result := make([]byte,hex.EncodedLen(len(buffer)))
	hex.Encode(result,buffer)
	fmt.Println(string(result))
}