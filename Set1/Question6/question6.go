package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"os"
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
	var low, score float64
	low = 400.0
	msg := ""
	key := byte(0)

	for i:=0;i<127;i++{
		k:=byte(i)
		buffer := xorBytes(input,k)
		score = getScore(buffer)
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
	score := 0.0
	var buffer float64
	for i,val := range counter{
		buffer1 := math.Pow((val-idealFreqs[i]),2)
		buffer = buffer1/idealFreqs[i]
		score =score+ buffer
	}
	return score
}
func getScore(input string)(float64){
	input_buffer := input
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

func hammingDistance(a,b[]byte)(int){
	sum :=0
	for i := range a{
		r := a[i]^b[i]
		for r>0{
			if r&1==1{
				sum++
			}
			r=r>>1
		}
	}
	return  sum
}

func guessKeySize (cipherText []byte) int{
	keyLen :=0
	maxDist := 400.0
	maxSize := 40
	blocks := len(cipherText)/maxSize
	for keySize :=2;keySize<maxSize;keySize++{
		dist := 0.0
		for i:=0;i<blocks;i++{
			a := i*keySize
			b := (i+1)*keySize
			c := (i+2)*keySize
			dist += float64(hammingDistance(cipherText[a:b],cipherText[b:c]))/float64(keySize)
		}
		dist /= float64(blocks)
		if dist <maxDist{
			maxDist = dist
			keyLen = keySize
		}
	}
	return keyLen
}

func guessKey(cipherText []byte, keySize int)string{
	key := ""
	blockSize := len(cipherText)/keySize
	for i:=0;i<keySize;i++{
		blocks := make([]byte,blockSize)
		for j:=0;j<blockSize;j++{
			blocks[j] = cipherText[i+j*keySize]
		}
		buffer,_ := bruetForce(blocks)
		key = key+buffer
	}
	return key
	}
func decrypt (key, cipherText []byte, keySize int)([]byte){
	plainText := make ([]byte, len(cipherText))
	j:=0
	for i,_:=range cipherText{
		plainText[i] = cipherText[i]^key[j]
		if (j+1)%keySize==0{
			j=0
			continue
		}
		j++
	}
	return plainText
}
func main(){
	filename := "question6_data.txt"
	filecontent, err := ioutil.ReadFile(filename)
	if err !=nil{
		fmt.Println("Input File Error")
		os.Exit(1)
	}
	cipherText,_ := base64.StdEncoding.DecodeString(string(filecontent))
	keyLen := guessKeySize(cipherText)
	key := guessKey(cipherText,keyLen)
	fmt.Println("Key = ", key)
	fmt.Println("\nPlainText is : ")
	fmt.Println(string(decrypt([]byte (key),cipherText,keyLen)))
}