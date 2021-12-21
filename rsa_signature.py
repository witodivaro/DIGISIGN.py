from lib import RSA

    
(e, d, N) = RSA.generate()

message = "hello world! I'm really proud to be here today."
hex_message = str.encode(message).hex()

tag = RSA.sign(d, N, hex_message)
valid = RSA.verify(e, N, hex_message, tag)

print(valid)