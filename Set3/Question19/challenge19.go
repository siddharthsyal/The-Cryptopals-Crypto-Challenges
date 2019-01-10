package main

import(
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strings"
	"time"
)
var blockSize = 16
var key = initKey()

func initKey()([]byte){
	rand.Seed(time.Now().UnixNano())
	key := make([]byte,blockSize)
	_,err := rand.Read(key)
	if err !=nil{
		fmt.Println("Key Issue")
		os.Exit(1)
	}
	return key
}

var idealFreqs = []float64{	.08167, .01492, .02792, .04253, .12702, .0228, .02015, .06094, .06966, .0153, .0772, .04025, .02406, .06749, .07507, .01929, .0095, .05987, .06327, .09056, .02758, .00978, .02360, .00150, .01974, .0074,0.23200}

func aesCTR_encrypt(plainText []byte)[]byte{
	var cipherText []byte
	tracker := 0
	i:=0
	cipherBlock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	var counter,nonce int64
	counter =0
	nonce =0
	nonce_byte := make([]byte,8)
	counter_byte := make([]byte,8)
	for len(cipherText)<len(plainText){
		buffer := make([]byte,blockSize)
		binary.LittleEndian.PutUint64(nonce_byte, uint64(nonce))
		binary.LittleEndian.PutUint64(counter_byte, uint64(counter))
		cipherBlock.Encrypt(buffer,append(nonce_byte,counter_byte...))
		for i=0;i<16;i++{
			if tracker==len(plainText)-1{
				return cipherText
			}
			cipherText = append(cipherText,buffer[i]^plainText[tracker])
			tracker++
		}
		nonce =0
		counter=0
	}
	return cipherText
}

func readByline(filename string)[]string{
	file,err := os.Open(filename)
	if err!=nil{
		fmt.Println("File read error")
		os.Exit(1)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	cipherText := make([]string,40)
	i:=0
	for scanner.Scan(){
		plaintext := make([]byte, base64.StdEncoding.DecodedLen(len(scanner.Bytes())))
		base64.StdEncoding.Decode(plaintext,scanner.Bytes())
		cipherText[i] = string(aesCTR_encrypt(plaintext))
		i++
		if i==40{
			return cipherText
		}
	}
	fmt.Println("\n\n")
	return cipherText
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

func bruteForce(input []byte)(byte){
	var low, score float64
	low = 400.0
	key := byte(0)
	for i:=0;i<256;i++{
		k:=byte(i)
		buffer := xorBytes(input,k)
		score = getScore(buffer)
		if score <  low{
			low = score
			key = k
		}
	}
	return key
}

func xorBytes(input []byte, key byte)(string){
	result := make([]byte,len(input))
	for i:=range input{
		result[i] = input[i]^key
	}
	return string(result)
}
func guessKeyStream(cipherText []string)[]byte{
	var key []byte
	for i:=0;i<16;i++{
		blocks := make([]byte,40)
		for j:=0;j<40;j++{
			blocks[j] = byte(cipherText[j][i])
		}
		buffer := bruteForce(blocks)
		key = append(key, buffer)
	}
	return key
}

func getPlainText(cipherText []string, key []byte){
	for  i:=0;i<40;i++{
		plaintext := make([]byte,len(cipherText[i]))
		for j:=0;j<len(cipherText[i]);j++{
			k := j%16
			plaintext = append(plaintext,byte(cipherText[i][j])^byte(key[k]))
		}
		fmt.Println(string(plaintext))
	}
}

func main(){
	filename := "challenge19_data.txt"
	cipherText := readByline(filename)
	getPlainText(cipherText,guessKeyStream(cipherText))
	}
