package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func padding_attacker(message string,length_user int)[]byte{
	buffer := []byte(message)
	buffer = append(buffer,0x80)
	padding := 64 - (len(message)+length_user + 9) % 64
	for i := 0; i < padding; i++ {
		buffer = append(buffer, 0x00)
	}
	length := uint64toBytes(uint64((len(message)+length_user) * 8))
	buffer = append(buffer[:len(buffer)], append([]byte{}, length...)...)
	return buffer
}

func getMD4_attacker(message string,length int)string{
	message_padded := padding_attacker(message,length)
	/*Enter the A,B,C,D values in little endian format */
	var A uint32 = 0x48cc5644
	var B uint32 = 0x3f29a1c4
	var C uint32 = 0x2675428b
	var D uint32 = 0xd9972de0
	for i:=0;i<=len(message_padded)-64;i+=64{
		x:=make([]uint32,16)
		buffer:=message_padded[i:i+64]
		for j:=0;j<16;j++{
			x[j]=binary.LittleEndian.Uint32(buffer[j*4:(j+1)*4])
		}
		AA:=A
		BB:=B
		CC:=C
		DD:=D

		//Round 1

		A = FF(A,B,C,D,0,3,x)
		D = FF(D,A,B,C,1,7,x)
		C = FF(C,D,A,B,2,11,x)
		B = FF(B,C,D,A,3,19,x)

		A = FF(A,B,C,D,4,3,x)
		D = FF(D,A,B,C,5,7,x)
		C = FF(C,D,A,B,6,11,x)
		B = FF(B,C,D,A,7,19,x)

		A = FF(A,B,C,D,8,3,x)
		D = FF(D,A,B,C,9,7,x)
		C = FF(C,D,A,B,10,11,x)
		B = FF(B,C,D,A,11,19,x)

		A = FF(A,B,C,D,12,3,x)
		D = FF(D,A,B,C,13,7,x)
		C = FF(C,D,A,B,14,11,x)
		B = FF(B,C,D,A,15,19,x)
		//Round 2

		A = GG(A,B,C,D,0,3,x)
		D = GG(D,A,B,C,4,5,x)
		C = GG(C,D,A,B,8,9,x)
		B = GG(B,C,D,A,12,13,x)

		A = GG(A,B,C,D,1,3,x)
		D = GG(D,A,B,C,5,5,x)
		C = GG(C,D,A,B,9,9,x)
		B = GG(B,C,D,A,13,13,x)

		A = GG(A,B,C,D,2,3,x)
		D = GG(D,A,B,C,6,5,x)
		C = GG(C,D,A,B,10,9,x)
		B = GG(B,C,D,A,14,13,x)

		A = GG(A,B,C,D,3,3,x)
		D = GG(D,A,B,C,7,5,x)
		C = GG(C,D,A,B,11,9,x)
		B = GG(B,C,D,A,15,13,x)

		//Round 3
		A = HH(A,B,C,D,0,3,x)
		D = HH(D,A,B,C,8,9,x)
		C = HH(C,D,A,B,4,11,x)
		B = HH(B,C,D,A,12,15,x)

		A = HH(A,B,C,D,2,3,x)
		D = HH(D,A,B,C,10,9,x)
		C = HH(C,D,A,B,6,11,x)
		B = HH(B,C,D,A,14,15,x)

		A = HH(A,B,C,D,1,3,x)
		D = HH(D,A,B,C,9,9,x)
		C = HH(C,D,A,B,5,11,x)
		B = HH(B,C,D,A,13,15,x)

		A = HH(A,B,C,D,3,3,x)
		D = HH(D,A,B,C,11,9,x)
		C = HH(C,D,A,B,7,11,x)
		B = HH(B,C,D,A,15,15,x)

		A = (A + AA)
		B = (B + BB)
		C = (C + CC)
		D = (D + DD)
	}
	return fmt.Sprintf("%08x%08x%08x%08x",littleToBigEndian(A),littleToBigEndian(B),littleToBigEndian(C),littleToBigEndian(D))
}


func length_extension_attack(old_message string){
	attack_message := ";admin=true"
	for j:=0;j<=512;j++{
		chunks := []byte(old_message)
		chunks = append(chunks, byte(0x80))
		padding := 64 - (len(old_message)+j + 9) % 64
		for i := 0; i < padding; i++ {
			chunks = append(chunks, 0x00)
		}
		ml := uint64toBytes(uint64((len(old_message)+j)*8))
		chunks = append(chunks[:len(chunks)], append([]byte{}, ml...)...)
		rogue_digest := getMD4_attacker(attack_message,len(chunks)+j)
		new_message := append(chunks,[]byte(attack_message)...)
		if receiverVerify(string(new_message),rogue_digest){
			fmt.Println("New Plaintext = ",string(new_message),"\nNew Digest Value =",string(rogue_digest))
			fmt.Println("Length Extension Attack SuccessFull")
			return
		}
	}
	fmt.Println("Bad Attack")
	return
}

/*The attacker does not have access to this func*/
func receiverVerify (userInput ,digest string)bool{
	secretKey := "2ab9eb0"
	plainText := secretKey+userInput
	digest_local := getMD4(plainText)
	if strings.Compare(digest,digest_local)==0{
		return true
	}
	return false
}

func reciever(userInput string)(string){
	secretKey := "2ab9eb0"
	plainText := secretKey+userInput
	digest := getMD4(plainText)
	return digest
}

func main(){
	userInput := "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	digest := reciever(userInput)
	fmt.Println("Before attack =",string(digest))
	length_extension_attack(userInput)
}