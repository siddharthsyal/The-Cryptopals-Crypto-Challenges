package srp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

var Email =  "email@email.com"
var password_client = []byte("StrongPassword123")
var clientSessionKey []byte
var n, clientSecret, ClientPub, g = setClientPublicKey()

func setClientPublicKey()(*big.Int,*big.Int,*big.Int,*big.Int){
	/***********Initializations*********/
	buffer_p:=new(big.Int)
	buffer_ClientSecret:=new(big.Int)
	buffer_ClientPub:=new(big.Int)
	buffer_g:=new(big.Int)
	/***********P*********************/
	filename := "value_p.txt"
	p_hex := getP(filename)
	p_unhex := make([]byte,hex.DecodedLen(len(p_hex)))
	hex.Decode(p_unhex,p_hex)
	buffer_p.SetBytes(p_unhex)
	/*********************************/
	buffer_ClientSecret = randomNumber(1024)
	buffer_g = big.NewInt(int64(2))
	buffer_ClientPub = squareANDmultiply(buffer_g,buffer_ClientSecret,buffer_p)
	return buffer_p,buffer_ClientSecret,buffer_ClientPub,buffer_g
}

func generateHMAC(salt []byte)string{
	h := hmac.New(sha256.New,[]byte(salt))
	h.Write(clientSessionKey)
	return string(HexEncode(h.Sum(nil)))
}

func GenerateClientSessionKey(salt_str, B_str string) string{
	/***********Initializations*********/
	uH := new(big.Int)
	buffer1 := new(big.Int)
	buffer2 := new(big.Int)
	B := new(big.Int)
	xH := new(big.Int)
	/*********Converting to Integer************/
	B.SetString(B_str,10)
	u_bytes := getBytes(ClientPub,B)
	uH.SetBytes(u_bytes)//uH = SHA256(A|B), u = integer of uH
	xH_bytes := sha256.Sum256(append(HexDecode([]byte(salt_str)),password_client...))// xH=SHA256(salt|password)
	xH.SetBytes(xH_bytes[:])
	/**************(a + u * x)********************/
	buffer1.Mul(uH,xH)//u * x
	buffer1.Add(buffer1,clientSecret)//(a + u * x)
	/**************(B - k * g**x)******************/
	buffer2 = squareANDmultiply(g,xH,n)//g**x
	buffer2.Mul(big.NewInt(int64(3)),buffer2)//k * g**x; k =3
	buffer2.Sub(B,buffer2)//(B - k * g**x)
	/****************S = (B - k * g**x)**(a + u * x) % N*****************/
	key := sha256.Sum256(squareANDmultiply(buffer2,buffer1,n).Bytes())
	clientSessionKey= key[:]
	return generateHMAC(HexDecode([]byte(salt_str)))
}


