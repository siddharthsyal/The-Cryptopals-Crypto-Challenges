package srp

import (
	"crypto/rand"
	"crypto/sha256"
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


func getBytes(num1, num2 *big.Int)[]byte{
	num1_bytes := num1.Bytes()
	num2_bytes := num2.Bytes()
	data := append(num1_bytes,num2_bytes...)
	result := sha256.Sum256(data)
	return result[:]
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

func HexDecode(data []byte)[]byte{
	result := make([]byte, hex.DecodedLen(len(data)))
	hex.Decode(result,data)
	return result
}

func HexEncode(data []byte)[]byte{
	result := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(result,data)
	return result
}