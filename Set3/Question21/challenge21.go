package main

import (
	"fmt"
	"os"
)

const (
	w uint32 = 32
	n uint32 = 624
	m uint32 = 397
	r uint32 = 31
	u uint32 = 11
	d uint32 = 0xFFFFFFFF
	t uint32 = 15
	c uint32 = 0xEFC60000
	l uint32 = 18
	f uint32 = 1812433253
	s uint32 = 7
	b uint32 = 0x9D2C5680
	a  uint32 = 0x9908B0DF
	lower_mask uint32 = 0x7FFFFFFF
	uper_mask uint32 = 0x80000000
)

var MT, index = init_var()

func init_var()([]uint32,uint32){
	return make([]uint32,n),n+1
}

func seed_mt(seed uint32){
	var i uint32
	index = n
	MT[0] = seed
	for i=1;i<n;i++{
		MT[i]=0xFFFFFFFF&(f*(MT[i-1]^(MT[i-1]>>(w-2)))+i)
	}
}
func extract_number()uint32{
	if index >=n{
		if index>n{
			fmt.Println("Generator was never seeded")
			os.Exit(1)
		}
		twist()
	}
	var y uint32 = MT[index]
	y = y^((y>>u)&d)
	y = y^((y<<s)&b)
	y = y^((y<<t)&c)
	y=y^(y>>l)
	index++
	return 0xFFFFFFFF&y
}
func twist(){
	var i uint32
	for i=0;i<n;i++{
		var x uint32 = (MT[i]&uper_mask)+(MT[(i+1)%n]&lower_mask)
		var xA uint32 = x>>1
		if (x%2)!=0{
			xA=xA^a
		}
		MT[i]= MT[(i+m)%n]^xA
	}
	index =0
}

func main(){
	seed_mt(5489)
	for i:=0;i<5;i++{
		fmt.Println(extract_number())
	}
}