package main

import(
	"bytes"
	"encoding/binary"
	"fmt"
)

func padding(message string)[]byte{
	buffer := []byte(message)
	buffer = append(buffer,0x80)
	padding := 64 - (len(message) + 9) % 64
	for i := 0; i < padding; i++ {
		buffer = append(buffer, 0x00)
	}
	length := uint64toBytes(uint64(len(message) * 8))
	buffer = append(buffer[:len(buffer)], append([]byte{}, length...)...)
	return buffer
}

func uint64toBytes(data uint64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, data)
	return buf.Bytes()
}

func F(x,y,z uint32)uint32{
	return ((x&y)|((^x)&z))
}

func G(x,y,z uint32)uint32{
	return ((x&y)|(x&z)|(y&z))
}

func H(x,y,z uint32)uint32{
	return (x^y^z)
}
func FF(a,b,c,d,k,s uint32,X []uint32)uint32{
	return (ROL((a+F(b,c,d)+X[k]),s))
}

func GG(a,b,c,d,k,s uint32,X[]uint32)uint32{
	return (ROL((a+G(b,c,d)+X[k]+ 0x5A827999),s))
}
func HH(a,b,c,d,k,s uint32,X[]uint32)uint32{
	return (ROL((a+H(b,c,d)+X[k]+0x6ED9EBA1),s))
}

/*Func for left rotating the input*/
func ROL(n, b uint32) uint32 {
	return ((n << b) | (n >> (32 - b)))
}

func littleToBigEndian(input uint32)uint32{
	buffer := make([]byte,4)
	binary.LittleEndian.PutUint32(buffer,input)
	return binary.BigEndian.Uint32(buffer)
}
func getMD4(message string)string{
	message_padded := padding(message)
	/*Enter the A,B,C,D values in little endian format */
	var A uint32 = 0x67452301
	var B uint32 = 0xefcdab89
	var C uint32 = 0x98badcfe
	var D uint32 = 0x10325476
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