package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

var idealFreqs = []float64{	.08167, .01492, .02792, .04253, .12702, .0228, .02015, .06094, .06966, .0153, .0772, .04025, .02406, .06749, .07507, .01929, .0095, .05987, .06327, .09056, .02758, .00978, .02360, .00150, .01974, .0074,0.23200}

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

func getScore(input string)(float64){
	input_buffer := strings.ToLower(input)
	counter := make([]float64,27)
	total :=0
	for _,ch := range input_buffer{
		if 'a'<=ch&&ch<='z'{
			counter[int(ch)-int('a')]++
			total++
		}
		if int(ch) == 32{
			total++
			counter[26]++
		}
	}
	for i,val := range counter{
		counter[i]=val/float64(total)
	}
	score := chiSquare(counter,float64(len(input)))
	return score
}
func chiSquare(counter []float64,total float64)(float64){
	score := 0.0
	var buffer float64
	for i,_ := range counter{
		expected := total*idealFreqs[i]
		buffer1 := math.Pow(counter[i]-expected,2)
		buffer = buffer1/(expected)
		score =score+ buffer
	}
	return score
}

func main(){
	cipherText_hex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipherText := HexDecode([]byte(cipherText_hex))
	key, msg := bruetForce(cipherText)
	fmt.Println(key)
	fmt.Println(msg)

}
