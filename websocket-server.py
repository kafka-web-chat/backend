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
import time
from ckafka import KafkaClient

import utils

SERVER_CONFIG = json.load(open('config.json', 'r'))
SECRET = base64.b64decode(SERVER_CONFIG['secret'])

users_db = TinyDB('users.db.json').table('users')

# ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# ssl_context.load_verify_locations('certs/ws/cert.pem')

event_loop = asyncio.get_event_loop()

class Client:
	def __init__(self, socket, path):
		self.socket = socket
		self.token = path[1:]

		self.kafka = None
		self.username = None
		self.key = None

	async def main(self):
		print('main')

		if self.token == 'check':
			return

		username, password= utils.parse_token(self.token)

		if username == None:
			print('Username is none')
			return await self.socket.close()

		user = users_db.get(Query().username == username)

		if user == None:
			print('User is none')
			return await self.socket.close()


		self.username = user.get('username')
		print('New client: %s' % self.username)

		key = RSA.importKey(base64.b64decode(user.get("private_key")))

		self.kafka = KafkaClient(self.username, password, key)

		await asyncio.gather(
			self.ws_kafka_thread(),
			self.user_ws_thread()
		)

	async def ws_kafka_thread(self):
		while True:
			message = await event_loop.run_in_executor(None, self.read_next_message)

			if message != None:
				await self.sendChatMessage(message)

	def read_next_message(self):
		encrypted_message = self.kafka.next()
		message = None

		try:
			message = self.kafka.decryptMessage(encrypted_message)
		except Exception as e:
			print("Error on %s: " % self.username, e)

		return message

	async def user_ws_thread(self):
		while True:
			data = await self.socket.recv()
			data = json.loads(data)

			msg_type = data.get('type')

			if msg_type == 'send-message':
				to = data.get('to')
				text = data.get('text')

				if type(to) is not type(text) is not str:
					continue

				user = users_db.get(Query().username == self.username)

				for contact in user.get('contacts'):
					if contact.get('username') == to:

						contact_key = contact.get('key')
						contact_key = RSA.importKey(base64.b64decode(contact_key))

						message_packet = json.dumps({
							'source': self.username,
							'plain': text,
							'timestamp': int(time.time() * 1000)
						})

						self.kafka.producer.send(to, value=self.kafka.encryptMessage(message_packet, contact_key))
						self.kafka.producer.flush()

						break

	async def notify(self, text):
		await self.socket.send(json.dumps({
			"type": "notification",
			"text": text,
		}))

	async def sendChatMessage(self, message):
		await self.socket.send(json.dumps({
			"type": "chat-message",
			"message": message,
		}))

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
