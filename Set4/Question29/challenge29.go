package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func sha1_user(message string,length int) string {

	// Initialize variables:
	var h0 uint32 = 0x660aa45a
	var h1 uint32 = 0x3c99a80e
	var h2 uint32 = 0x049e4035
	var h3 uint32 = 0x2fd454d4
	var h4 uint32 = 0x7c783649

	// Pre-processing:
	chunks := []byte(message)

	// append the bit '1' to the message
	chunks = append(chunks, byte(0x80))

	// append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
	//    is congruent to 448 (mod 512)
	padding := 64 - (len(message)+length + 9) % 64
	for i := 0; i < padding; i++ {
		chunks = append(chunks, 0x00)
	}

	// append length of message (before pre-processing), in bits, as 64-bit big-endian integer
	ml := uint64ToBytes(uint64((len(message)+length) * 8))
	chunks = append(chunks[:len(chunks)], append([]byte{}, ml...)...)
	for i := 0; i < len(chunks); i+=64 {
		// Process the message in successive 512-bit chunks:
		// break message into 512-bit chunks
		words := make([]uint32, 80, 80)

		// break chunk into sixteen 32-bit big-endian words w[i]
		for j := 0; j < 16; j++ {
			chunk := chunks[i + j * 4:i + j * 4 + 4]
			words[j] = binary.BigEndian.Uint32(chunk)
		}

		// Extend the sixteen 32-bit words into eighty 32-bit words:
		for j := 16; j < 80; j++ {
			n := words[j - 3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16]
			words[j] = leftRotate(n, 1)
		}

		// Initialize hash value for this chunk:
		a := h0
		b := h1
		c := h2
		d := h3
		e := h4

		// Main loop:
		var f, k uint32
		for i := 0; i < 80; i++ {
			if 0 <= i && i <= 19 {
				f = d ^ (b & (c ^ d))
				k = 0x5A827999
			} else if 20 <= i && i <= 39 {
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			} else if 40 <= i && i <= 59 {
				f = (b & c) ^ (b & d) ^ (c & d)
				k = 0x8F1BBCDC
			} else if 60 <= i && i <= 79 {
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			a, b, c, d, e = leftRotate(a, uint32(5)) + f + e + k + words[i] & 0xffffffff, a, leftRotate(b, uint32(30)), c, d
		}

		// Add this chunk's hash to result so far:
		h0 = (h0 + a) & 0xffffffff
		h1 = (h1 + b) & 0xffffffff
		h2 = (h2 + c) & 0xffffffff
		h3 = (h3 + d) & 0xffffffff
		h4 = (h4 + e) & 0xffffffff
	}

	// Produce the final hash value (big-endian)
	return fmt.Sprintf("%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4)
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
		ml := uint64ToBytes(uint64((len(old_message)+j)*8))
		chunks = append(chunks[:len(chunks)], append([]byte{}, ml...)...)
		rogue_digest := sha1_user(attack_message,len(chunks)+j)
		new_message := append(chunks,[]byte(attack_message)...)
		if receiverVerify(string(new_message),rogue_digest){
			fmt.Println("New Plaintext = ",string(new_message),"\nNew Digest Value =",string(rogue_digest))
			fmt.Println("Length Extension Attack SuccessFull")
			return
		}
	}
}

/*This is not visible to the attacker*/
func receiverVerify (userInput ,digest string)bool{
	secretKey := "2ab9eb0"
	plainText := secretKey+userInput
	digest_local := Sha1(plainText)
	if strings.Compare(digest,digest_local)==0{
		return true
	}
	return false
}

func reciever(userInput string)(string){
	secretKey := "2ab9eb0"
	plainText := secretKey+userInput
	digest := Sha1(plainText)
	return digest
}

func main(){
	userInput := "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	digest := reciever(userInput)
	fmt.Println("Before attack =",string(digest))
	length_extension_attack(userInput)
}