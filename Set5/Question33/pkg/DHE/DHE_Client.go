package DHE

import (
	"encoding/hex"
	"math/big"
)
var clientSecret,clientPub *big.Int

func GetClientPublicKey()(string,string,string){
	filename := "value_p.txt"
	p_hex := getP(filename)
	p_unhex := make([]byte,hex.DecodedLen(len(p_hex)))
	hex.Decode(p_unhex,p_hex)
	p := new(big.Int)
	p.SetBytes(p_unhex)
	g := big.NewInt(int64(2))
	clientSecret = randomNumber(1024)
	clientPub = squareANDmultiply(g,clientSecret,p)
	return clientPub.String(),p.String(),g.String()
}

func GetClientKey(serverPub,p *big.Int)[]byte{
	return generateSymmetricKey(serverPub,clientSecret,p)
}