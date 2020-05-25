#!/usr/bin/env python3

from kafka import KafkaProducer
from ckafka import KafkaAdmin
from tinydb import TinyDB, Query
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.PublicKey import RSA
import hashlib
import base64
import json
import os


SERVER_CONFIG = json.load(open('config.json', 'r'))
SECRET = base64.b64decode(SERVER_CONFIG['secret'])

login_db = TinyDB('users.db.json').table('login')
users_db = TinyDB('users.db.json').table('users')

app = Flask("kafka-rest-api")
CORS(app)

def error(desc):
	return {
		"success": False,
		"error": desc,
	}

def success(data=None):
	return {
		"success": True,
		"data": data
	}

def gen_token(username, password):
	global SECRET

	data = b'%s$$%s$$%s' %  (
		base64.b64encode(username.encode()),
		base64.b64encode(password.encode()),
		base64.b64encode(os.urandom(32))
	)

	hmac = base64.b64encode(hashlib.pbkdf2_hmac('sha256', data, SECRET, 100000))

	return (data + b"$$" + hmac).decode()

def parse_token(token):
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

@app.route('/check', methods=['get'])
def check():
	return success();


# TODO:
@app.route('/user-exists/<username>', methods=['get'])
def user_exists(username):
	Users = Query()
	user_exists = login_db.get(Users.username == username) != None

	return {
		"success": True,
		"exists": user_exists
	}

@app.route('/register', methods=['post'])
def register():
	data = request.json

	if data == None:
		return error("Invalid JSON")

	username = data.get('username')
	password = data.get('password')

	if None in [username, password]:
		return error("Missing fields")

	if type(username) != str or type(password) != str:
		return error("Invalid data type")

	if len(username) == 0 or len(password) == 0:
		return error("Invalid data length")


	admin = KafkaAdmin()

	try:
		admin.createUser(username, password)
	except Exception as e:
		return error(str(e))

	raw_key = RSA.generate(2048)
	private_key = base64.b64encode(raw_key.exportKey(format="DER")).decode()

	users_db.insert({
		"username": username,
		"private_key": private_key,
		"contacts": [],
		"chat_history": [],
	})

	public_key = raw_key.publickey().exportKey(format="DER")
	public_key = base64.b64encode(public_key).decode()

	return success({
		"token": gen_token(username, password),
		"private_key": private_key,
		"public_key": public_key
	})


@app.route('/login', methods=['post'])
def login():
	data = request.json

	if data == None:
		return error("Invalid JSON")

	username = data.get('username')
	password = data.get('password')

	if None in [username, password]:
		return error("Missing fields")

	if type(username) != str or type(password) != str:
		return error("Invalid data type")

	if len(username) == 0 or len(password) == 0:
		return error("Invalid data length")


	try:
		proc = KafkaProducer(
			sasl_plain_username = username,
			sasl_plain_password = password,
			bootstrap_servers= 'kafkaproject.ddns.net:9091',
			security_protocol= 'SASL_SSL',
			sasl_mechanism= 'SCRAM-SHA-512',
			ssl_cafile= 'certs/kafka/rootCA.crt',
		)

		proc.close()
	except Exception as e:
		return error('Invalid credentials')


	private_key = users_db.get(Query().username == username).get('private_key', 'NONE')

	public_key = RSA.importKey(base64.b64decode(private_key)).publickey()
	public_key = base64.b64encode(public_key.exportKey(format="DER")).decode()

	return success({
		"token": gen_token(username, password),
		"private_key": private_key,
		"public_key": public_key,
	})

@app.route('/get-chat-history', methods=['post'])
def get_chat_history():
	data = request.json

	if data == None:
		return error("Invalid JSON")

	token = data.get('token')

	if not token:
		return error('Token required')

	currentUser, _ = parse_token(token)

	if not currentUser:
		return error('Invalid token')

	user_object = users_db.get(Query().username == currentUser)

	return success(user_object.get('chat_history'))

@app.route('/get-contacts', methods=['post'])
def get_contacts():
	data = request.json

	if data == None:
		return error("Invalid JSON")

	token = data.get('token')

	if not token:
		return error('Token required')

	currentUser, _ = parse_token(token)

	if not currentUser:
		return error('Invalid token')

	user_object = users_db.get(Query().username == currentUser)

	return success(user_object.get('contacts'))

@app.route('/delete-contact', methods=['post'])
def delete_contact():
	data = request.json

	if data == None:
		return error("Invalid JSON")

	token = data.get('token')

	if not token:
		return error('Token required')

	currentUser, _ = parse_token(token)

	if not currentUser:
		return error('Invalid token')

	username = data.get('username')

	if username is None:
		return error("Missing fields")

	if type(username) != str:
		return error("Invalid data type")

	if len(username) == 0:
		return error("Invalid data length")

	query = Query().username == currentUser
	user_object = users_db.get(query)

	contacts = user_object.get('contacts')

	index = None

	for i, contact in contacts:
		if contact.get('username') == username:
			index = i
			break

	if index != None:
		del contacts[i]

	user_object.update({"contacts": contacts})
	users_db.update(user_object, query)

	return success()

@app.route('/add-contact', methods=['post'])
def add_contact():
	data = request.json

	if data == None:
		return error("Invalid JSON")

	token = data.get('token')

	if not token:
		return error('Token required')

	currentUser, _ = parse_token(token)

	if not currentUser:
		return error('Invalid token')

	username = data.get('username')
	key = data.get('key')

	if None in [username, key]:
		return error("Missing fields")

	if type(username) != str or type(key) != str:
		return error("Invalid data type")

	if len(username) == 0 or len(key) == 0:
		return error("Invalid data length")


	contact = {
		"username": username,
		"key": key
	}

	query = Query().username == currentUser
	user_object = users_db.get(query)

	contacts = user_object.get('contacts')

	if contact in contacts:
		return error("Contact already exists")

	contacts.append(contact)
	user_object.update({"contacts": contacts})

	users_db.update(user_object, query)

	return success()



if __name__ == '__main__':
	app.run(host='0.0.0.0', port=SERVER_CONFIG['rest_api_port'])
