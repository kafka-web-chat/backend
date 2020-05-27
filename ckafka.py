#!/usr/bin/env python3
from kafka import KafkaConsumer, KafkaProducer, KafkaAdminClient
from kafka.admin.acl_resource import ACLOperation, ACLPermissionType, ACLFilter, ACL, ResourcePattern, ResourcePatternFilter, ResourceType, ACLResourcePatternType
from kafka.admin.config_resource import ConfigResource, ConfigResourceType
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as PKCS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import Crypto.Util.Padding as Padding
import Crypto.Util.number
from Crypto.Util.number import ceil_div, size
import base64
import os

import socket
import ssl

KAFKA_CONFIG = {
	'bootstrap_servers': ['kafkaproject.ddns.net:9091', 'lmn806.ddns.net:9091'],
	'security_protocol': 'SASL_SSL',
	'sasl_mechanism': 'SCRAM-SHA-512',
	'ssl_cafile': 'certs/kafka/rootCA.crt',
	'api_version': (0, 10, 1)
}

class KafkaAdmin:
	def __init__(self):
		self.admin = KafkaAdminClient(
			sasl_plain_username = 'admin',
			sasl_plain_password = '1234567890qw',
			**KAFKA_CONFIG
		)

	def createUser(self, username, password):
		if username in self.admin.list_topics():
			raise Exception('User already exists')

		HOST = 'kafkaproject.ddns.net'
		PORT = 8081

		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
			context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
			context.check_hostname = False
			context.verify_mode = ssl.CERT_NONE
			sock = context.wrap_socket(sock)

			sock.connect((HOST, PORT))

			packet = b'CREA' + ('%s@@%s' % (username, password)).encode('iso-8859-1')

			packet = (len(packet)).to_bytes(4, 'big') + packet

			sock.send(packet)

	def listTopics(self):
		return self.admin.list_topics()

class KafkaClient:
	def __init__(self, username, password, rsa_key):
		self.username = username
		self.password = password
		self.rsa_key = rsa_key

		print('Login with %s and %s' % (username, password))

		self.consumer = KafkaConsumer(username,
		        sasl_plain_username = username,
			sasl_plain_password = password,
			group_id=None,
		        **KAFKA_CONFIG,
		)

		self.producer = KafkaProducer(
			sasl_plain_username = username,
			sasl_plain_password = password,
			**KAFKA_CONFIG,
		)

	def next(self):
		return next(self.consumer)

	def decryptMessage(self, message):
		data = message.value.decode().split('$$')

		iv = base64.b64decode(data[0])
		encryptedKey = base64.b64decode(data[1])
		encryptedMessage = base64.b64decode(data[2])

		key = PKCS.new(self.rsa_key, hashAlgo=SHA256).decrypt(encryptedKey)

		cipher = AES.new(key, AES.MODE_CBC, iv=iv)
		plain_message = Padding.unpad(cipher.decrypt(encryptedMessage), 32)

		return plain_message.decode()

	def encryptMessage(self, message, public_key):
		iv = os.urandom(16)
		message_key = os.urandom(32)

		cipher = AES.new(message_key, AES.MODE_CBC, iv=iv)
		encryptedMessage = cipher.encrypt(Padding.pad(message.encode(), 32))

		encryptedKey = PKCS.new(public_key, hashAlgo=SHA256).encrypt(message_key)

		encodedChunks =  list(map(base64.b64encode, [iv, encryptedKey, encryptedMessage]))

		return b'$$'.join(encodedChunks)
