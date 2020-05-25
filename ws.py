#!/usr/bin/env python3

import threading
import asyncio
import pathlib
import ssl
import websockets
from tinydb import TinyDB, Query
from Crypto.PublicKey import RSA
import hashlib
import base64
import json
from ckafka import KafkaClient

SERVER_CONFIG = json.load(open('config.json', 'r'))
SECRET = base64.b64decode(SERVER_CONFIG['secret'])

login_db = TinyDB('users.db.json').table('login')
users_db = TinyDB('users.db.json').table('users')

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations('certs/ws/cert.pem')

event_loop = asyncio.get_event_loop()

class Client:
	def __init__(self, socket, path):
		self.socket = socket
		self.token = path[1:]

		self.kafka = None
		self.user = None
		self.key = None

	async def main(self):

		if self.token == 'check':
			return

		username, password= self.parse_token(self.token)

		if username == None:
			print('Username is none')
			return await self.socket.close()

		self.user = users_db.get(Query().username == username)

		if self.user == None:
			print('User is none')
			return await self.socket.close()

		print('New client: %s' % self.user.get('username'))

		key = RSA.importKey(base64.b64decode(self.user.get("private_key")))

		print(key.has_private())

		self.kafka = KafkaClient(self.user.get('username'), password, key)

		await asyncio.gather(
			self.ws_kafka_thread(),
			self.user_ws_thread()
		)

	async def ws_kafka_thread(self):
		while True:
			message = await event_loop.run_in_executor(None, self.read_next_message)

			if message != None:
				await self.sendChatMessage(message)

	async def user_ws_thread(self):
		while True:
			data = await self.socket.recv()
			data = json.loads(data)

			print('ws recv: ', data)
			type == data.get('type')

			if type == 'send-message':
				to = data.get('to')
				text = data.get('text')

				if type(to) is not type(text) is not str:
					continue

				self.kafka.producer.send(to, value=self.kafka.encryptMessage(text))

	def read_next_message(self):
		print('gonna message')
		encrypted_message = self.kafka.next()
		message = None

		print('read new message')

		try:
			message = self.kafka.decryptMessage(encrypted_message)
		except Exception as e:
			print("Error on %s: " % self.user.get('username'), e)

		return message

	def parse_token(self, token):
		global SECRET

		username, password, salt, token_hmac = token.split("$$")

		data = ('%s$$%s$$%s' % (username, password, salt)).encode()

		hmac = base64.b64encode(hashlib.pbkdf2_hmac('sha256', data, SECRET, 100000)).decode()

		if token_hmac == hmac:
			return [
				base64.b64decode(username).decode(),
				base64.b64decode(password).decode()
			]

		return [None, None]

	async def notify(self, text):
		await self.socket.send(json.dumps({
			"type": "notification",
			"text": text,
		}))

	async def sendChatMessage(self, message):
		print('sending %s' % message)
		await self.socket.send(json.dumps({
			"type": "chat-message",
			"message": message,
		}))
		print('sended')

	async def close():
		await self.socket.close()


async def client_handler(websocket, path):
	client = Client(websocket, path)
	await client.main()


async def ws_main(websocket, path):
	client = Client(websocket, path)
	await client.main()
	print("End client")

start_server = websockets.serve(
    ws_main, "0.0.0.0", SERVER_CONFIG['websocket_port'], reuse_port=True #, ssl=ssl_context
)

event_loop.run_until_complete(start_server)
event_loop.run_forever()
