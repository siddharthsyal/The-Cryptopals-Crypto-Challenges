package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strings"
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

var idealFreqs = []float64{	.08167, .01492, .02792, .04253, .12702, .0228, .02015, .06094, .06966, .0153, .0772, .04025, .02406, .06749, .07507, .01929, .0095, .05987, .06327, .09056, .02758, .00978, .02360, .00150, .01974, .0074,0.23200}

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