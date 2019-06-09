package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
)

func squareANDmultiply(x,y,n *big.Int)*big.Int{//result = g^r mod p
	var g,r,p big.Int
	p.Set(n)
	g.Set(x)
	r.Set(y)
	result := big.NewInt(1)
	for r.BitLen()>0{
		if r.Bit(0)!=0{
			result.Mul(result,&g)
			result.Mod(result,&p)
		}
		r.Rsh(&r,1)
		g.Mul(&g,&g)
		g.Mod(&g,&p)
	}
	return result
}

func exponentiation(num *big.Int,exp *big.Int,result *big.Int){
	var p,r big.Int
	p.Set(exp)
	r.Set(num)
	buffer := big.NewInt(1)
	result.Set(buffer)
	for p.BitLen()>0{
		if p.Bit(0)!=0 {
			result.Mul(result,&r)

		}
		p.Rsh(&p,1)
		r.Mul(&r,&r)
	}
}

func getP(filename string)[]byte{
	data, err := ioutil.ReadFile(filename)
	if err!=nil{
		fmt.Println("Check Input Filename")
		os.Exit(1)
	}
	return data
}

func randomNumber(bitSize int)(*big.Int){
	var upper_limit big.Int
	bigSize_big := big.NewInt(int64(bitSize))
	exponentiation(big.NewInt(int64(2)),bigSize_big,&upper_limit)
	number,err := rand.Int(rand.Reader,&upper_limit)
	if err!=nil{
		fmt.Println("Error Generating Random Number")
		os.Exit(1)
	}
	return number
}

func pubkeyAlice(p,g *big.Int)(*big.Int,*big.Int){
	aliceSecret := randomNumber(1024)
	pubKey := squareANDmultiply(g,aliceSecret,p)
	return pubKey,aliceSecret
}

func pubkeyBob(p,g *big.Int)(*big.Int,*big.Int){
	bobSecret := randomNumber(1024)
	pubKey := squareANDmultiply(g,bobSecret,p)
	return pubKey,bobSecret
}

func generateSymmetricKey(pubAlice,pubBob,secretBob,secretAlice,p *big.Int){
	alice_key := squareANDmultiply(pubBob,secretAlice,p)
	bob_key := squareANDmultiply(pubAlice,secretBob,p)
	if alice_key.Cmp(bob_key)==0{
		fmt.Println("Successful DHE")
	}
	return
}

func main(){
	filename := "value_p.txt"
	p_hex := getP(filename)
	p_unhex := make([]byte,hex.DecodedLen(len(p_hex)))
	hex.Decode(p_unhex,p_hex)
	p := new(big.Int)
	p.SetBytes(p_unhex)
	g := big.NewInt(int64(2))
	pubAlice,secretAlice :=pubkeyAlice(p,g)
	pubBob,secretBob :=pubkeyBob(p,g)
	generateSymmetricKey(pubAlice,pubBob,secretBob,secretAlice,p)
}