Implement DH with negotiated groups, and break with malicious "g" parameters

A->B
    Send "p", "g"
B->A
    Send ACK
A->B
    Send "A"
B->A
    Send "B"
A->B
    Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
    Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

Do the MITM attack again, but play with "g". What happens with:

    g = 1 (PART 1)
    g = p
    g = p - 1

Write attacks for each. 