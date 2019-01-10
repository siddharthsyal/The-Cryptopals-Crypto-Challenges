package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strings"
)

var idealFreqs = []float64{	.08167, .01492, .02792, .04253, .12702, .0228, .02015, .06094, .06966, .0153, .0772, .04025, .02406, .06749, .07507, .01929, .0095, .05987, .06327, .09056, .02758, .00978, .02360, .00150, .01974, .0074,0.23200}}

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