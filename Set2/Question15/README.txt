PKCS#7 padding validation

Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string

ICE ICE BABYx04x04x04x04

... has valid padding, and produces the result ICE ICE BABY.

The string

ICE ICE BABYx05x05x05x05

... does not have valid padding, nor does

ICE ICE BABYx01x02x03x04

If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.