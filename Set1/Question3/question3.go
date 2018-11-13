package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

var idealFreqs = []float64{
	.0817, .0149, .0278, .0425, .1270, .0223, .0202, .0609, .0697, .0015, .0077, .0402, .0241,
	.0675, .0751, .0193, .0009, .0599, .0633, .0906, .0276, .0098, .0236, .0015, .0197, .0007}

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
		buffer = math.Pow((val-idealFreqs[i]),2)
		buffer = buffer/idealFreqs[i]
		score += buffer
	}
	return score
}
func getScore(input string)(float64){
	input = strings.ToLower(input)
	total :=0
	counter := make([]float64,26)
	for _,ch := range input{
		if 'a'<=ch&&ch<='z'{
			counter[int(ch)-97]++
			total ++
		}
	}
	for i,val := range counter{
		counter[i]=val/float64(total)
	}
	score := chiSquare(counter)
	return score
}

func main(){
	cipherText_hex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipherText := HexDecode([]byte(cipherText_hex))
	key, msg := bruetForce(cipherText)
	fmt.Println(string(key))
	fmt.Println(msg)

}
