Break repeating-key XOR

This challenge isn't conceptually hard, but it involves actual error-prone coding. 

The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

-> Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
->Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
  "this is a test" and "wokka wokka!!!"is 37. Make sure your code agrees before you proceed.
->For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
->The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. 
  Or take 4 KEYSIZE blocks instead of 2 and average the distances.
->Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
->Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
->Solve each block as if it was single-character XOR. You already have code to do this.
->For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
