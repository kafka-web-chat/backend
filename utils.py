import hashlib
import base64
import json
import os

SERVER_CONFIG = json.load(open('config.json', 'r'))
SECRET = base64.b64decode(SERVER_CONFIG['secret'])

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

	try:
		username, password, salt, token_hmac = token.split("$$")

		data = ('%s$$%s$$%s' % (username, password, salt)).encode()

		hmac = base64.b64encode(hashlib.pbkdf2_hmac('sha256', data, SECRET, 100000)).decode()

		if token_hmac == hmac:
			return [
				base64.b64decode(username).decode(),
				base64.b64decode(password).decode()
			]
	except Exception as e:
		pass


	return [None, None]
