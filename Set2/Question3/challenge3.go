package main

import(
	"crypto/aes"
	"math"
	"math/rand"
	"fmt"
	"os"
	"time"
)

func xorBytes(a,b[]byte)[]byte{
	result := make ([]byte,16)
	for i,_ := range a{
		result[i] = a[i]^b[i]
	}
	return result
}

func aesCBC(plaintext , key []byte)[]byte{
	blocksize := 16
	if len(plaintext)%blocksize != 0{
		fmt.Println("Padding Error")
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err !=nil{
		fmt.Println("Cipher Block Error")
		os.Exit(1)
	}
	cipherText := make([]byte,len(plaintext))
	rand.Seed(time.Now().UnixNano())
	iv := make ([]byte, blocksize)
	_,err = rand.Read(iv)
	if err !=nil{
		fmt.Println("IV Error")
		os.Exit(1)
	}
	for i:=0;i<len(plaintext);i=i+blocksize{
		if i==0{
			buffer := xorBytes(plaintext[i:i+blocksize],iv)
			cipherBlock.Encrypt(cipherText[i:i+blocksize],buffer)
		}else if i!=0{
			buffer := xorBytes(plaintext[i:i+blocksize],cipherText[i-blocksize:i])
			cipherBlock.Encrypt(cipherText[i:i+blocksize],buffer)
		}
	}
	return cipherText
}

func aesECB(plaintext , key []byte)[]byte{
	blocksize := 16
	if len(plaintext)%blocksize !=0{
		fmt.Println("Padding Error")
		os.Exit(1)
	}
	cipherBlock,err := aes.NewCipher(key)
	if err!=nil{
		fmt.Println("AES error")
		os.Exit(1)
	}
	cipherText := make([]byte,len(plaintext))
	for i:=0;i<len(plaintext);i=i+blocksize{
		cipherBlock.Encrypt(cipherText[i:i+blocksize],plaintext[i:i+blocksize])
	}
	return cipherText
}

func randomData(plaintext[]byte)[]byte{
	r :=rand.New(rand.NewSource(time.Now().UnixNano()))
	max :=11
	p:=0
	for p<5{
		p = r.Intn(max)
	}
	buffer := make ([]byte, p)
	rand.Seed(time.Now().UnixNano())
	_,_ = rand.Read(buffer)
	buffer_str := string(buffer)+string(plaintext)+string(buffer)
	plaintext_padded := make([]byte,len(plaintext)+p+p)
	copy(plaintext_padded,[]byte(buffer_str))
	return plaintext_padded
}
func paddingPKCS7(plainText []byte , blockSize int) []byte{
	padding :=blockSize - int(math.Mod(float64(len(plainText)),float64(blockSize)))
	for i:= 0;i<padding;i++{
		plainText= append(plainText,byte(padding))
	}
	return plainText
}
func detectECB (cipherText []byte) bool{
	tracker := make(map[string]int)
	init := false
	for i:=16;i<=len(cipherText);i++{
		if !init{
			tracker[string(cipherText[i-16:i])]=1
			init = true
		}else{
			if _,ok := tracker[string(cipherText[i-16:i])];ok==true{
				return ok
			}else{
				tracker[string(cipherText[i-16:i])]=1
			}
		}
	}
	return false
}

func main (){
	rand.Seed(time.Now().UnixNano())
	r :=rand.New(rand.NewSource(time.Now().UnixNano()))
	max := 3
	p:=0
	for p==0{
		p = r.Intn(max)
	}
	key := make([]byte,16)
	_,err := rand.Read(key)
	if err != nil{
		fmt.Println("Key Error")
	}
	plaintext := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if p==1{
		fmt.Println("Selected mode : CBC")
		plaintext := randomData([]byte(plaintext))
		cipherText := aesCBC(paddingPKCS7(plaintext,16),key)
		if detectECB(cipherText)==false{
			fmt.Println("Detected Mode: CBC")
		}
		}else if p==2{
		fmt.Println("Selected mode : ECB")
		plaintext := randomData([]byte(plaintext))
		cipherText := aesECB(paddingPKCS7(plaintext,16),key)
		if detectECB(cipherText)==true{
			fmt.Println("Detected Mode: ECB")
		}
	}

}
