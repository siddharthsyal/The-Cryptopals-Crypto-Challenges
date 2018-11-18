package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strings"
	"unicode/utf8"
)
func xorBytes(input []byte, key []byte)(string){
	result_buffer := make([]byte, len(input))
	keySize := len(key)
	j:=0
	for i,_ := range input{
		result_buffer[i]=input[i]^ key[j]
		j++
		if j==keySize{
			j=0
		}
	}
	return string(result_buffer)
}

var idealFreqs = []float64{
	8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61,
	6.95,7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09,0.17, 2.11, 0.07}

func HexDecode(input []byte)([]byte){
	cipherText := make([]byte,hex.DecodedLen(len(input)))
	hex.Decode(cipherText,input)
	return cipherText
}
func bruteForce(input []byte)(byte, string,float64){
	var low float64
	flag := false
	msg := ""
	key := byte(0)

	for i:=0;i<256;i++{
		buffer := xorBytes(input,[]byte(string(i)))
		score := getScore(buffer)
		if flag==false{
			low = score
			flag = true
		}else if score <= low&&flag==true{
			low = score
			key = byte(i)
			msg = buffer
		}
	}
	return key,msg,low
}

func chiSquare(counter []float64)(float64){
	var score,buffer float64
	for i,val := range counter{
		buffer = math.Pow((val-idealFreqs[i]),2)
		buffer = buffer/idealFreqs[i]
		score += buffer
	}
	return score
}
func getScore(input string)(float64){
	input = strings.ToLower(input)
	counter := make([]float64,26)
	for _,ch := range input{
		if 'a'<=ch&&ch<='z'{
			counter[int(ch)-97]++
		}
	}
	for i,val := range counter{
		counter[i]=val/float64(utf8.RuneCountInString(input))
	}
	score := chiSquare(counter)
	return score
}


func main(){
	message := ""
	var key byte
	var cipherText string
	flag := false
	var min float64
	filename := "question4_data.txt"
	filecontent, err := ioutil.ReadFile(filename)
	if err !=nil{
		fmt.Println("File Input Error")
		os.Exit(1	)
	}
	filecontent_byte := bytes.Split(filecontent,[]byte("\n"))
	for _,cipherText_hex := range filecontent_byte{
		cipherText_unhex := HexDecode([]byte(cipherText_hex))
		key_buffer,msg,score := bruteForce(cipherText_unhex)
		if flag==false{
			min = score
			flag =true
		}else if score < min{
			cipherText = string(cipherText_hex)
			min = score
			message = msg
			key = key_buffer
		}
	}
	fmt.Println("Message = ",message)
	fmt.Println("Key = ",key)
	fmt.Println("cipherText = ",cipherText)
}