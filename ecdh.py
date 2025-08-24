from Crypto.PublicKey import ECC

# Generate ECC private key
U = ECC.generate(curve='p256')
private_key_pem = U.export_key(format='PEM')
public_key_pem = U.public_key().export_key(format='PEM')


# Write the private key to a file
with open("ecdh-private_key.pem", "w") as priv_file:
    priv_file.write(private_key_pem)

# Write the public key to a file
with open("ecdh-public_key.pem", "w") as pub_file:
    pub_file.write(public_key_pem)
