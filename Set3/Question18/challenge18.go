package main

import(
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
)
var key = []byte("YELLOW SUBMARINE")
var blockSize = 16


func aesCTR_decrypt(cipherText []byte)[]byte{
	var plainText []byte
	tracker := 0
	i:=0
	block_count :=0
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
	if len(cipherText)%blockSize==0{
		block_count = len(cipherText)/blockSize
	}else{
		block_count = len(cipherText)/blockSize
		block_count++
	}
	for len(plainText)<=len(cipherText){
		buffer := make([]byte,blockSize)
		binary.LittleEndian.PutUint64(nonce_byte, uint64(nonce))
		binary.LittleEndian.PutUint64(counter_byte, uint64(counter))
		cipherBlock.Encrypt(buffer,append(nonce_byte,counter_byte...))
		for i=0;i<16;i++{
			if tracker==len(cipherText)-1{
				return plainText
			}
			plainText = append(plainText,buffer[i]^cipherText[tracker])

			tracker++
		}
		nonce =0
		counter++
	}
	return plainText
}

func main(){
	ciphertext_bs64 := []byte("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	cipherText := make([]byte,base64.StdEncoding.DecodedLen(len(ciphertext_bs64)))
	_,err := base64.StdEncoding.Decode(cipherText,ciphertext_bs64)
	if err !=nil{
		fmt.Println("Decoding Issue")
		os.Exit(1)
	}
	fmt.Println(string(aesCTR_decrypt(cipherText)))

}