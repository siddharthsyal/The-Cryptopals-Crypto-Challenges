Break HMAC-SHA1 with a slightly less artificial timing leak

Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)

Now break it again.

Note : The server is configured for 5ms delay timer.