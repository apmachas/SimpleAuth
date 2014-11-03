# Author: Machas Apostolos
# E-mail: ap.machas@gmail.com, a.machas@dias.aueb.gr

# Software is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

#! /usr/bin/python
import urllib
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import ssl
import socket
import sqlite3
import json
import os

con = sqlite3.connect('AuthServer.db')
cursor = con.cursor()
from keyczar import keyczart
from keyczar.keys import RsaPrivateKey, RsaPublicKey

if os.path.exists("AuthKeys"): # If Key File exists
	f = file("AuthKeys", "r+")
	AuthKeys=RsaPrivateKey.Read(f.read()) #Read RSA key pair
else: # Else
	f = file("AuthKeys", "w")
	AuthKeys = RsaPrivateKey.Generate()# Generate RSA key pair
	f.write(str(AuthKeys))# Write Keys to File
# Server's Hostname (Change To Server's IP Address"
ServerHostname = '0.0.0.0'
class ReqHandler(BaseHTTPRequestHandler):

# Accepts a standard HTTP call.
	"""
	Policy: The policy request refers to
	Username: User's Username
	Password: User's Password
	AuthMsg: Authentication Message (Token)
	CloudKey: Cloud Providers Public Key

	Get Method used for authenticating to a Policy (Singing a token) or getting Access Control Provider's Public Key and Policy URL
	Put Method used for creating/editing a Policy
	"""
	def do_GET(self): 
	# retrieving required data
		Policy = self.path
		Username = self.headers.get('X-Auth-User')	
		Password = self.headers.get('X-Auth-Pass')
		AuthMsg = self.headers.get('X-Auth-Message')
		CloudKey = self.headers.get('X-Public-Key')
		
		if not AuthMsg:
			# If not Authentication Message specified
			sql = "SELECT * FROM Policies WHERE Policy=?"
			cursor.execute(sql , [Policy])
			i = cursor.fetchone()
			if not i:
			# If the specified Policy can not be found
				self.send_error(404)
			else:
			# Sending Policy URL and Server's Public Key to user
				self.send_response(200)
				self.send_header("X-Policy-Url", ServerHostname+Policy)
				self.send_header("X-Public-Key", str(AuthKeys.public_key))
				self.end_headers()
			return		
		# Checking Credentials and Cloud Providers Key
		if not Username or not Password :
			self.send_error(401, 'No Credentials Specified')
			return
		
		if not CloudKey:
			self.send_error(400)
			return
		# Retrieving data for the requested Policy
		sql = "SELECT AccessLevel, Time FROM Policies JOIN Users WHERE Policy=? AND Users.Username=? AND Password=?"
		cursor.execute(sql , [Policy, Username, Password])
		i = cursor.fetchone()

		if not i :
			self.send_error(401, 'Wrong Credentials Or Policy')
			return
	
		else :
			try:
				
				token = json.loads(AuthMsg).get('X-Auth-Token')
				SavedAcl = i[0]
				SavedTime = i[1]
				# Creating the Authentication Message and its Signature
				authmessage = ServerHostname+Policy+token+SavedTime+SavedAcl+CloudKey
				message = '{"X-Auth-Token" : "'+token+'" , "X-Token-Time" : "'+SavedTime+'" , "X-Access-Level" : "'+SavedAcl+'"}'
				sign = AuthKeys.Sign(authmessage)
				self.send_response(200)
				self.send_header("X-Auth-Message", message)
				self.send_header("X-Signature",sign.encode('hex'))
				self.end_headers()
				return
			
			except:
				self.send_error(400)	
				return


	def do_PUT(self):
		# retrieving required data
		Policy = self.path
		Username = self.headers.get('X-Auth-User')
		Password = self.headers.get('X-Auth-Pass')
		Time = self.headers.get('X-Time') # Access Time for the new user
		# Checking Credentials And Time
		sql = "SELECT * FROM Users WHERE Username=? AND Password=?"
		cursor.execute(sql , [Username, Password])
		i = cursor.fetchone()
		
		if not (i or Time):		
			self.send_error(401)
			return
		else:
			sql = "SELECT * FROM Policies WHERE Policy=?"
			cursor.execute(sql , [Policy])
			i = cursor.fetchone()
			if not i: 
			# Creating a new Policy for user with owner privileges (Access Level = 4)
			# Updating db file
				cursor.execute("INSERT INTO Policies VALUES (?,?,?,?)",[Policy, Username, '4',Time])
				con.commit()
				self.send_response(201)
				self.send_header("X-Policy-Url", ServerHostname+Policy)
				self.send_header("X-Public-Key", str(AuthKeys.public_key))
				self.end_headers()
				return
			else:
			#If policy allready exists
				sql = "SELECT * FROM Policies JOIN Users WHERE Policy=? AND Users.Username=? AND Password=? AND AccessLevel=4"
				cursor.execute(sql , [Policy, Username, Password])
				i = cursor.fetchone()

				if not i :
				# if user is does not has the privileges to edit the policy (Access Level = 4)
					self.send_error(401, 'YOU CANOT EDIT THIS POLICY')
					return
					
				# Getting new users Username and Access Level
				User = self.headers.get('X-User')
				Accl = self.headers.get('X-Access-Level')
				
				if not (User or Accl):
					self.send_error(400)
					return

				sql = "SELECT * FROM Users WHERE Username=?"
				cursor.execute(sql , [User])
				i = cursor.fetchone()

				if not i :
					self.send_error(404, 'USER DOES NOT EXISTS')
					return
				# Delete previous registries of the specified user & policy
				cursor.execute("DELETE FROM Policies WHERE Policy=? AND Username=?",[Policy,User])
				con.commit()
				# Update db file
				cursor.execute("INSERT INTO Policies VALUES (?,?,?,?)",[Policy, User, Accl,Time])
				con.commit()
				self.send_response(201)
				return
def run():
	print ('AuthServer: Server is starting...')
	# Creating Tables
	cursor.execute(""" CREATE TABLE IF NOT EXISTS Users
          	( Username text, Password text,
                 	PRIMARY KEY (Username))""")
	cursor.execute(""" CREATE TABLE IF NOT EXISTS Policies
            	(Policy text , Username text, AccessLevel text, Time text,
                  PRIMARY KEY (Policy, Username), FOREIGN KEY(Username) REFERENCES USERS(Username))""")
	#Starting Server
	server_address = (ServerHostname, 443)
	httpd = HTTPServer(server_address, ReqHandler)
	httpd.socket = ssl.wrap_socket (httpd.socket, certfile = 'cert.crt',keyfile="cert.key", server_side = True)
	print ('AuthServer: Server is running...')
	httpd.serve_forever()


if __name__ == '__main__':
	run()
