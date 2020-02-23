Break SRP with a zero key

Get your SRP working in an actual client-server setting. "Log in" with a valid password using the protocol.

Now log in without your password by having the client send 0 as its "A" value. What does this to the "S" value that both sides compute?

Now log in without your password by having the client send N, N*2