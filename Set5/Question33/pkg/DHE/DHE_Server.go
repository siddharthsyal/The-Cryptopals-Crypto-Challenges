package DHE

import (
	"math/big"
)
var serverSecret,serverPub *big.Int

func GetServerKey(clientPub,p *big.Int)[]byte{
	return generateSymmetricKey(clientPub,serverSecret,p)
}

func GetServerPublicKey(p_client, g_client *big.Int)string{
	p := new(big.Int)
	p.Set(p_client)
	g := new(big.Int)
	g.Set(g_client)
	serverSecret = randomNumber(1024)
	serverPub = squareANDmultiply(g,serverSecret,p)
	return serverPub.String()
}