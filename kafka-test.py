#!/usr/bin/env python3
from kafka import KafkaConsumer, KafkaProducer, KafkaAdminClient
from kafka.admin.config_resource import ConfigResource, ConfigResourceType
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as PKCS
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import Crypto.Util.Padding as Padding
import Crypto.Util.number
from Crypto.Util.number import ceil_div, size
import json
import base64
import os

import socket
import ssl

def decryptMessage(rsa_key, message):
	data = message.value.decode().split('$$')

	iv = base64.b64decode(data[0])
	encryptedKey = base64.b64decode(data[1])
	encryptedMessage = base64.b64decode(data[2])

	print("Encrypted key[%s]: %s" % (len(encryptedKey), encryptedKey))

	key = PKCS.new(rsa_key, hashAlgo=SHA256).decrypt(encryptedKey)

	print('Decrypted key: %s' % key)

	cipher = AES.new(key, AES.MODE_CBC, iv=iv)
	plain_message = Padding.unpad(cipher.decrypt(encryptedMessage), 32)

	return plain_message.decode()

key = RSA.importKey(open('cipher/keys/0.key', 'rb').read())

print(json.dumps({
	"username": "test3",
	"publickey": base64.b64encode(key.publickey().exportKey(format="DER")).decode(),
}))

KAFKA_CONFIG = {
	'bootstrap_servers': ['kafkaproject.ddns.net:9091', 'lmn806.ddns.net:9091'],
	'security_protocol': 'SASL_SSL',
	'sasl_mechanism': 'SCRAM-SHA-512',
	'ssl_cafile': 'certs/kafka/rootCA.crt',
	'api_version': (0, 10, 1)
}

consumer = KafkaConsumer('test3',
        sasl_plain_username = 'test3',
	sasl_plain_password = 'Ab321321',
	group_id=None,
        **KAFKA_CONFIG,
)


for msg in consumer:
	try:
		print(decryptMessage(key, msg))
	except Exception as e:
		pass




# self.producer = KafkaProducer(
# 	sasl_plain_username = username,
# 	sasl_plain_password = password,
# 	**KAFKA_CONFIG,
# )

# def next(self):
# 	return next(self.consumer)
#

#
# def encryptMessage(self, message):
# 	iv = os.urandom(16)
# 	key = os.urandom(32)
#
# 	cipher = AES.new(key, AES.MODE_CBC, iv=iv)
# 	encryptedMessage = cipher.encrypt(Padding.pad(message.encode(), 32))
#
# 	encryptedKey = PKCS.new(self.rsa_key).encrypt(key)
#
# 	encodedChunks =  list(map(base64.b64encode, [iv, encryptedKey, encryptedMessage]))
#
# 	return b'$$'.join(encodedChunks)
