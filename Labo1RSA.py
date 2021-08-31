import sys 
  from Crypto.PublicKey import RSA 
  from Crypto.Cipher import PKCS1_OAEP 
  
bit_size = int (sys.argv[1]) 
  key_format = sys.argv[2] 
  text2cipher = sys.argv[3] 
 keys = RSA.generate (bit_size) 
 
#Importamos la clave pC:blica para cifrar los datos
  cipher_rsa = PKCS1_OAEP.new (keys.publickey ()) 
#Importamos la clave privada para descifrar los datos
  decipher_rsa = PKCS1_OAEP.new (keys) 
#Ciframos los datos.
  enc_data = cipher_rsa.encrypt (text2cipher.encode ()) 
#Desciframos los datos
  dec_data = decipher_rsa.decrypt (enc_data) 
  
print ("Encriptado:") 
print (enc_data, end = 'nn') 
 
print ("Desencriptado:") 
 print (dec_data)
