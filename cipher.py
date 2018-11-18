import binascii
from Crypto.Cipher import AES

def xor_blocks(b1, b2):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(b1, b2))

def encrypt(m, p, iv):
	aes = AES.new(p, AES.MODE_CBC, iv)
	return aes.encrypt(m)

def decrypt_block(c, k):
	aes = AES.new(k, AES.MODE_ECB)
	return aes.decrypt(c)


# Partial key
partial_key = "9aF738g9AkI112"
# Secret message
message = "The message is protected by AES!"
# Cipher block 1
cipher_block_1 = binascii.unhexlify('808e200a54806b0e94fb9633db9d67f0')
# Known cipher block 0 bytes
partial_cipher_block_0 = {
			0: "\x9E",
			14: "\x43",
			15: "\x6A"
}

# List of all chars
chars = [chr(x) for x in range(128)]

# Finding correct keys:
possible_keys = []
for ch1 in chars:
	for ch2 in chars:
		# Create 16 bytes key
		possible_key = partial_key + ch1 + ch2
		# Decrypt last block
		decrypted_block_1 = decrypt_block(cipher_block_1, possible_key)
		# Check if XORing first cipher block with decrypted second block results in correct message for first and last bit
		check_first_bit = message[16] == chr(ord(decrypted_block_1[0]) ^ ord(partial_cipher_block_0[0]))
		check_last_bit = message[31] == chr(ord(decrypted_block_1[15]) ^ ord(partial_cipher_block_0[15]))
		if(check_first_bit and check_last_bit):
			possible_keys.append(possible_key)
print(possible_keys)

# Now we have complete key, complete cipher block 1
# We can guess cipher block 0
# Cipher block 0 = Decrypted cipher block 1 XOR message[16:]
possible_ivs = []
for correct_key in possible_keys:
	decrypted_block_1 = decrypt_block(cipher_block_1, correct_key)
	cipher_block_0 = xor_blocks(decrypted_block_1, message[16:])

	# Now that we have the complete cipher block 0 and key
	# We can guess the IV of the encryption
	# IV = Decrypted cipher block 0 XOR message[:16]
	decrypted_block_0 = decrypt_block(cipher_block_0, correct_key)
	iv = xor_blocks(decrypted_block_0, message[:16])
	possible_ivs.append(iv)

print(possible_ivs)



