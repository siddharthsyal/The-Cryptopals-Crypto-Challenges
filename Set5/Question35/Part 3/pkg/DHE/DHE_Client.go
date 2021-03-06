package DHE

import (
	"encoding/hex"
	"math/big"
)
var clientSecret,clientPub *big.Int

func GetClientPublicKey()(string,string,string){
	var g big.Int
	filename := "value_p.txt"
	p_hex := getP(filename)
	p_unhex := make([]byte,hex.DecodedLen(len(p_hex)))
	hex.Decode(p_unhex,p_hex)
	p := new(big.Int)
	p.SetBytes(p_unhex)
	g.Sub(p,big.NewInt(1))
	clientSecret = randomNumber(1024)
	clientPub = squareANDmultiply(&g,clientSecret,p)
	return clientPub.String(),p.String(),g.String()
}

func GetClientKey(serverPub,p *big.Int)[]byte{
	return GenerateSymmetricKey(serverPub,clientSecret,p)
}