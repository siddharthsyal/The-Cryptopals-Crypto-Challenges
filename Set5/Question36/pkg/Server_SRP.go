package srp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
)

/*******************Initializations************************/
var password = []byte("StrongPassword123")
var serverSessionKey []byte
var Salt_Server = setSalt()
var n_Server = setN()
var v_Server, g_Server = InitV()
var serverSecret, ServerPublicKey = setPubKey()
var B_Server = setKeyMaterial()
/*********************************************************/

func setSalt()[]byte{
	salt_local := make([]byte, 20)
	_,err := rand.Read(salt_local)
	if err !=nil{
		fmt.Println("Server: Salt generation error. Process Aborted")
		os.Exit(1)
	}
	return HexEncode(salt_local)
}

func getHash()[]byte{
	Hash := sha256.Sum256(append(HexDecode(Salt_Server),password...))
	return Hash[:]
}

func setN()*big.Int{
	buffer := new(big.Int)
	filename := "value_p.txt"
	p_hex := getP(filename)
	p_unhex := HexDecode(p_hex)
	buffer.SetBytes(p_unhex)
	return buffer
}

func InitV()(*big.Int,*big.Int){
	x := new(big.Int)
	g_local := new(big.Int)
	Hash := getHash()
	x.SetBytes(Hash)//Converting Bytes to Number
	g_local = big.NewInt(int64(2))
	return squareANDmultiply(g_local,x,n_Server),g_local
}

func setPubKey()(*big.Int,*big.Int){
	var buffer_ServerSecret, buffer_ServerPublicKey *big.Int
	buffer_ServerSecret = randomNumber(1024)
	buffer_ServerPublicKey = squareANDmultiply(g_Server,buffer_ServerSecret,n_Server)
	return buffer_ServerSecret,buffer_ServerPublicKey
}

func setKeyMaterial()*big.Int{
	buffer := new(big.Int)
	buffer.Mul(v_Server,big.NewInt(int64(3)))//kv
	buffer.Add(buffer,ServerPublicKey)//B=kv + g**b % N
	return buffer
}

func VerifyHMAC(message []byte)bool{
	mac := hmac.New(sha256.New, HexDecode(Salt_Server))
	mac.Write(serverSessionKey)
	return hmac.Equal(HexDecode(message),mac.Sum(nil))
}

func GenerateSessionKey_Server(clientPubKey *big.Int){
	u := new(big.Int)
	buffer := new(big.Int)
	u_bytes := getBytes(clientPubKey,B_Server)//uH = SHA256(A|B), u = integer of uH
	u.SetBytes(u_bytes)
	buffer = squareANDmultiply(v_Server,u,n_Server)
	buffer.Mul(clientPubKey,buffer)//(A*(v^u))
	key := sha256.Sum256(squareANDmultiply(buffer,serverSecret,n_Server).Bytes())
	serverSessionKey= key[:]
	return
}