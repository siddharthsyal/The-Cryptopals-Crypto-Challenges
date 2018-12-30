package main

import(
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"
)

var blocksize = 16
var key,randomBytes = initKey()

func initKey()([]byte,[]byte){
	rand.Seed(time.Now().UnixNano())
	key := make([]byte,blocksize)
	_,err := rand.Read(key)
	if err !=nil{
		fmt.Println("Key Issue")
		os.Exit(1)
	}
	randLength := rand.Intn(255)
	randomBytes := make([]byte,randLength)
	_,err = rand.Read(randomBytes)
	if err !=nil{
		fmt.Println("Random Bytes Issue")
		os.Exit(1)
	}

	return key,randomBytes
}

func paddingPKCS7(plainText []byte ) []byte{
	padding :=blocksize - int(math.Mod(float64(len(plainText)),float64(blocksize)))
	for i:= 0;i<padding;i++{
		plainText= append(plainText,byte(padding))
	}
	return plainText
}

func lookupTable(prefix []byte,startpos int,number int)map[string]byte{
	var i byte
	tracker := make(map[string]byte)
	for i=0;i<128;i++{
		prefix_min := bytes.Repeat([]byte("A"),number)
		buffer := append(prefix,i)
		buffer_new := append(prefix_min,buffer...)
		cipherText := aesECB_encrypt(buffer_new)
		tracker[string(cipherText[startpos:startpos+blocksize])]=i
	}
	return tracker
}

func crackECB(unknownText []byte)[]byte{
	var plainText []byte
	number,startPos := getStartPos(unknownText)
	for i:=blocksize;i<len(unknownText);i=i+blocksize{
		var decrypted []byte
		for j:=blocksize-1;j>=0;j--{
			prefix_min:= bytes.Repeat([]byte("A"),number)
			prefix_new := append(bytes.Repeat([]byte("A"),j),decrypted...)
			lookup := lookupTable(prefix_new,startPos,number)
			buffer := append(bytes.Repeat([]byte("A"),j),unknownText[i-blocksize:i]...)
			prefix_both := append(prefix_min,buffer...)
			cipherText := aesECB_encrypt(prefix_both)
			decrypted = append(decrypted,lookup[string(cipherText[startPos:+startPos+blocksize])])
		}
		plainText = append(plainText,decrypted...)
	}
	return plainText
}


func aesECB_encrypt(plaintext_normal[]byte)[]byte{
	plaintext_new := append(randomBytes,plaintext_normal...)
	plaintext := paddingPKCS7(plaintext_new)
	if len(plaintext)%blocksize !=0{
		fmt.Println("Padding Error")
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	cipherText := make([]byte,len(plaintext))
	for i:=0;i<len(plaintext);i=i+blocksize{
		cipherBlock.Encrypt(cipherText[i:i+blocksize],plaintext[i:i+blocksize])
	}
	return cipherText
}

func getStartPos(plainText []byte)(int, int){
	for i:=0;;i++{
		plainText_new := append(bytes.Repeat([]byte("A"),i),plainText...)
		cipherText := aesECB_encrypt(plainText_new)
		for j:=blocksize;j<len(cipherText)-blocksize;j=j+blocksize{
			if bytes.Equal(cipherText[j-blocksize:j],cipherText[j:j+blocksize]){
				return i-(2*blocksize),j-blocksize
			}
		}
	}
	return 0,0
}



func main(){
	unkownString_base64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	len := base64.StdEncoding.DecodedLen(len(unkownString_base64))
	unknownstring := make([]byte,len)
	_,err:=base64.StdEncoding.Decode(unknownstring,[]byte(unkownString_base64))
	if err != nil{
		fmt.Print("Unknown string encoding issue")
		os.Exit(1)
	}
	fmt.Println(string(crackECB(unknownstring)))
	}