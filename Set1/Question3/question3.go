package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

var idealFreqs = []float64{
	8.04, 1.54, 3.06, 3.99, 12.51, 2.30, 1.96, 5.49, 7.26, 0.16, 0.67, 4.14, 2.53,
	7.09,7.60, 2.00, .11, 6.12, 6.54, 9.25, 2.71, 0.99, 1.92,0.19, 1.73, 0.09}

func HexDecode(input []byte)([]byte){
	cipherText := make([]byte,hex.DecodedLen(len(input)))
	hex.Decode(cipherText,input)
	return cipherText
}

func bruetForce(input []byte)(string, string){
	low := 1000.0
	msg := ""
	key := byte(0)

	for i:=0;i<256;i++{
		k:=byte(i)
		buffer := xorBytes(input,k)
		score := getScore(buffer)
		if score < low{
			low = score
			key = k
			msg = buffer
		}
	}
	return string(key), msg
}

func xorBytes(input []byte, key byte)(string){
	result := make([]byte,len(input))
	for i:=range input{
		result[i] = input[i]^key
	}
	return string(result)
}

func chiSquare(counter []float64)(float64){
	var score,buffer float64
	for i,val := range counter{
		buffer1 := math.Pow((val-idealFreqs[i]),2)
		buffer = buffer1/idealFreqs[i]
		score =score+ buffer
	}
	return score
}
func getScore(input string)(float64){
	input_buffer := input
	input_buffer = strings.ToLower(input_buffer)
	counter := make([]float64,26)
	for _,ch := range input_buffer{
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
	cipherText_hex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipherText := HexDecode([]byte(cipherText_hex))
	key, msg := bruetForce(cipherText)
	fmt.Println(key)
	fmt.Println(msg)

}
