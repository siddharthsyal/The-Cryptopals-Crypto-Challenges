package main

import(
	"crypto/sha1"
)

var blocksize = sha1.BlockSize

func xorBytes(a,b []byte)([]byte){
	buffer := make([]byte,len(a))
	for i,_ := range a{
		buffer[i]=a[i]^b[i]
	}
	return buffer
}

func hmac(message ,key []byte)[]byte{
	var opad, ipad []byte
	k := make([]byte,blocksize)
	/*Step 1*/
	if len(key)>blocksize{
		temp := sha1.Sum(key)
		copy(k,temp[:])
	}else{
		padding := blocksize-len(key)
		for i:=0;i<padding;i++{
			key = append(key,byte(0))
		}
		copy(k,key[:])
	}
	/*Generating iPad and oPad*/
	for i:=0;i<blocksize;i++{
		opad = append(opad,0x36)
	}
	for i:=0;i<blocksize;i++{
		ipad = append(ipad,0x5c)
	}
	/*Step 2*/
	ipad_xor := xorBytes(k,ipad)
	/*Step 3*/
	ipad_xor_data := append(ipad_xor,message...)
	/*Step 4*/
	buffer := sha1.Sum(ipad_xor_data)
	/*Step 5*/
	opad_xor := xorBytes(k,opad)
	/*Step 6*/
	opad_xor_data:= append(opad_xor,buffer[:]...)
	temp := sha1.Sum(opad_xor_data)
//	copy(final_result,temp[:])
	return temp[:]
}