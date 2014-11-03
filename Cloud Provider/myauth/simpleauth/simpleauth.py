# Author: Machas Apostolos
# E-mail: ap.machas@gmail.com, a.machas@dias.aueb.gr

# Software is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

from time import gmtime, strftime, time
from traceback import format_exc
from urllib import quote, unquote
from uuid import uuid4
import hmac
from Crypto.Random import atfork
import json
import sqlite3
from swift.common.middleware.acl import clean_acl
from swift.common.swob import Response, Request
from swift.common.swob import HTTPBadRequest, HTTPForbidden, HTTPUnauthorized, HTTPNotFound
import swift.common.wsgi
from swift.common.utils import split_path, cache_from_env
from keyczar.keys import RsaPrivateKey, RsaPublicKey

class SimpleAuth(object):
	"""
    Authentication and authorization system.
	

    Add to your pipeline in proxy-server.conf, such as::

        [pipeline:main]
        pipeline = catch_errors cache simpleauth proxy-server

    And add a simpleauth filter section, such as::

        [filter:simpleauth]
		use = egg:myauth#simpleauth
		DB_File = DataBaseFile.db

    See the proxy-server.conf-sample for more information.

    :param app: The next WSGI app in the pipeline
    :param conf: The dict of configuration values

	"""
	def __init__(self,app,conf):
		"""
		This method gets called when Proxy-Server (re)starts.
		Checks Proxy's Configuration File for the DB file destination
		If no file is set it creates the default DB file at /etc/swift/SimpleAuth.db		
		"""
		self.app = app
		self.conf = conf
		self.reseller_prefix = conf.get('reseller_prefix', 'AUTH').strip()
       		if self.reseller_prefix and self.reseller_prefix[-1] != '_':
            		self.reseller_prefix += '_'
		#Creating the db file, and Table
		self.dbfile = conf.get('DB_File')
		if not self.dbfile or not self.dbfile.endswith('.db'):
			self.dbfile = '/etc/swift/SimpleAuth.db'
		
		print 'SimpleAuth: Using "' + self.dbfile + '" As Database File'
		self.conn = sqlite3.connect(self.dbfile)
		self.cursor = self.conn.cursor()
		self.cursor.execute(""" CREATE TABLE IF NOT EXISTS AuthServers
                   			(PolicyUrl text , AuthServerKey text, File_Path text,
                    			PRIMARY KEY (PolicyUrl,File_Path))""") 	
		#Generating The RSA Keys
		self.CloudKeys = RsaPrivateKey.Generate()					
		self.accessLevel = 0
	

	def __call__ (self, environ, start_response):
		atfork()		
		"""
		Accepts a standard WSGI application call.
		If the request method isn't PUT/COPY and if the HTTP request contains the X-Auth-Server header
		it passes the request to PathCheck method
		Otherwise if it contains a token it makes the appropriate checks before it passes 
		the request to the final app
		"""
		self.conn = sqlite3.connect(self.dbfile)
		self.cursor = self.conn.cursor()

		def my_response (status, response_headers, exc_info=None):
		# sub-method committing the changes at database file when app-server's response is 200, 201 or 204
			st = str(status)[0:3]	
			Pass = [200,201,204]
			if int(st) in Pass:
				print >> self.logfile, 'SimpleAuth: commited'
				self.conn.commit()
			write = start_response(status, response_headers, exc_info)
			def _write(body_data): write(body_data)					
			return _write

		req = Request(environ)
		self.logfile =  environ['wsgi.errors'] 
		print >> self.logfile, 'SimpleAuth: __call__ started'
		authmsg = req.headers.get('X-Auth-Message')
		authsign = req.headers.get('X-Signature')
		token = req.headers.get('X-Auth-Token')
		# If the request does not contains a 'X-Auth-Message' Header
		if req.method =='GET' and not authmsg:
			print >> self.logfile, 'SimpleAuth: start PathCheck'
			return  self.PathCheck(environ, start_response)

		elif req.method =='PUT' and not authmsg:
			print >> self.logfile, 'SimpleAuth: start AddAccount'
			return  self.AddAccount(environ, start_response)
		# Else
		elif authmsg:
			print >> self.logfile, 'SimpleAuth: AuthMessage'

			try:
				if authsign:
					authsign =authsign.decode('hex')
				message = json.loads(authmsg)
			except:
				# in case the Authentication Message is invalid
				return HTTPBadRequest()(environ, start_response)
			token = message.get('X-Auth-Token')
			memcache_client = cache_from_env(environ)

			if not memcache_client:
				raise Exception ('Memcache required')

			# check if the token in Authentication Message is valid
			memcache_token_key = '%s/token/%s' % (self.reseller_prefix, token)
			cached_auth_data = memcache_client.get(memcache_token_key)

			if not  cached_auth_data :				
				# in case the token is not found
				return HTTPUnauthorized()(environ, start_response)
			filePolicy, acpKey, path = self.GetPolicy(req)

			if not filePolicy : 
				return HTTPNotFound()(environ, start_response)
						# retrieving token data
			published,tokenPolicy, authenticated, self.accessLevel = cached_auth_data

			# if the token specified was generated for a different policy than the "ACP-authenticated" one
			if not (tokenPolicy == filePolicy):
				return HTTPUnauthorized()(environ,start_response)

			# if authentication label is set to false
			if not authenticated:
					# updating token parameters
					if not (self.AuthenticateToken(environ,message,filePolicy,published, authsign,acpKey)):
						return HTTPUnauthorized()(environ, start_response)

			
			if req.method not in ('PUT' , 'COPY'):
				# if its not a PUT/COPY request
				print >> self.logfile, 'SimpleAuth: Starting Authorize'
				if req.method == 'DELETE':
					if self.accessLevel <2 :
					# request is denied
						return HTTPUnauthorized(request=req)
					else :
					# splitting request URL in version, account,container, object
						version, account, container, obj = split_path(req.path, 1, 4, True)
						path = req.path.replace(version,'')
						if path[-1] == '/':
							path = path[:-1]
						# updating db file
						sql = "DELETE FROM AuthServers WHERE File_Path=?"
						self.cursor.execute(sql , [(path)])
				# passing request to next WSGI app
				return self.app(environ, my_response)

			else:

				print >> self.logfile, 'SimpleAuth: Put / Copy'
				copyfrom = req.headers.get('X-Copy-From')
				if not copyfrom and (req.method == 'PUT'):
					# Put request
					if self.accessLevel <1 :
					# request is denied
						return HTTPUnauthorized()(environ, start_response)
					authkey = req.headers.get('X-Public-Key')
					authurl = req.headers.get('X-Policy-Url')
					#getting policy URL of the new file and Access Control Provider's Key
					if (not authkey) or (not authurl):
					# request is denied
						return HTTPBadRequest()(environ, start_response)
					try:
						# Updating Table with the new Policy and Key
						sql = "DELETE FROM AuthServers WHERE File_Path=?"
						self.cursor.execute(sql , [(path)])
						self.cursor.execute("INSERT INTO AuthServers VALUES ('"
						+authurl.replace('\'','').replace('\"','')+"' , '" 
						+authkey.replace('\'','')+"' , '"
						+path.replace('\'','').replace('\"','')+ "' )")
						
					except:
						return HTTPBadRequest()(environ, start_response)
					# passing request to next WSGI app
					environ ['swift.authorize'] = self.authorize
					environ ['swift.clean_acl'] = clean_acl
					return self.app(environ, my_response)
					
				else:
					# splitting request URL in version, account,container, object
					version, account, container, obj = split_path(req.path, 1, 4, True)
					if copyfrom and (req.method == 'PUT'):
						# If its a PUT request using Copy-From header
						if self.accessLevel <1 :
							return HTTPUnauthorized()(environ, start_response)
						if not container:
							return HTTPBadRequest()(environ, start_response)
						print >> self.logfile, 'SimpleAuth: Copying using Put'
						# getting the full 'copy-from' path
						source = '//'+account + copyfrom
						if source[-1]=='/':
							source=source[:-1]
						copyDestination = path


					elif destination and (req.method == 'COPY'):
						# Copying using Copy Command
						print >> self.logfile, 'SimpleAuth: Copying using Copy-Command'
						
						if self.accessLevel <1 :
							return HTTPUnauthorized()(environ, start_response)
						source = path
						copyDestination = '//'+account +destination 
						if copyDestination[-1]=='/':
							copyDestination=copyDestination[:-1]


					else:
						return HTTPBadRequest()(environ, start_response)
					sql = "SELECT * FROM AuthServers WHERE File_Path=?"
					self.cursor.execute(sql , [(source)])
					values = self.cursor.fetchone()
					if values:
						
						sql = "DELETE FROM AuthServers WHERE File_Path=?"
						self.cursor.execute(sql , [(copyDestination)])
						self.cursor.execute("INSERT INTO AuthServers VALUES ('"+values[0]+"','"+values[1]+"','"+copyDestination+ "')")					
						# passing request to next WSGI app
						environ ['swift.authorize'] = self.authorize
						environ ['swift.clean_acl'] = clean_acl
						return self.app(environ, my_response)
					else:
						print >> self.logfile, 'SimpleAuth: EDO'
						return HTTPNotFound()(environ,start_response)

		else:
			return HTTPUnauthorized()(environ,start_response)
		
	def authorize(self,req):	
		
		return None

	def GetPolicy (self, req) :
		try:	# splitting request URL in version, account,container, object
			version,account, container, obj = split_path(req.path, 1, 4, True)
			path = req.path.replace(version,'')
		except:
			return None, None, None
		if req.method == 'COPY' :
			destination = req.headers.get('Destination')
			if not destination:
				return None, None, None
			path = account+destination
		# removing symbol '/'
		if path[-1] == '/':
			path = path[:-1]
		# fetching data from database
		sql = "SELECT * FROM AuthServers WHERE File_Path=?"
		self.cursor.execute(sql , [(path)])
		q = self.cursor.fetchone()
		if not q:
			# if requested file isn't found
			if req.method not in ('PUT' , 'COPY'):
				# and its not a 'PUT'/'COPY' request
				return None, None, None
			else : 
				version, account, container, obj = split_path(req.path, 1, 4, True)
				# If its a 'PUT' request
				if req.method == 'PUT':
					# checking the account or container path
					if obj :						
						tmppath = path.replace(obj,'')
					elif container :
						tmppath = path.replace(container,'')
					else :
						return None, None, None
					
				else:
					destContainer , destObj = string.rsplit('/',1)
					tmppath = account+destContainer
				if tmppath[-1] == '/':
					tmppath = tmppath[:-1]
				self.cursor.execute(sql , [tmppath])
				q = self.cursor.fetchone()
				if not q: 
					# if account or container are not found
					return None, None, None
		
		try:
			# retrieving policy and Access Control Provider's key specified for the requested file 
			filePolicy = str(q[0])
			key = str(q[1])
			return filePolicy, key, path
		except:
			return None, None, None

	def AuthenticateToken(self,environ,message,Policy,published, sign,acpKey):
		currentTime = time()
		token = message.get('X-Auth-Token')
		self.accessLevel= message.get('X-Access-Level')
		Time = message.get('X-Token-Time')
		tempmessage = Policy+token+Time+self.accessLevel+str(self.CloudKeys.public_key)
		
		try:    
			# Verifying received Authentication Message with its Signature		
			acpKey = RsaPublicKey.Read(acpKey)
			if not acpKey.Verify(tempmessage,sign):
				return False
		
		except:
			return False
		expires = published + float(Time) # calculating the expiration time 
		if expires < currentTime:
			return False
		memcache_client = cache_from_env(environ)
		if not memcache_client:
			raise Exception ('Memcache required')
		memcache_token_key = '%s/token/%s' % (self.reseller_prefix, token)
		memcache_client.delete(memcache_token_key)
		memcache_client.set(memcache_token_key,(published,Policy,True,self.accessLevel),timeout = (expires-currentTime))
		return True

	def AddAccount(self,environ, start_response):
	
		req = Request(environ)
		# splitting request URL in version, account,container, object
		version,account, container, obj = split_path(req.path, 1, 4, True)
		# getting policy URL of the new account and Access Control Provider's Key
		authkey = req.headers.get('X-Public-Key')
		authurl = req.headers.get('X-Policy-Url')
		if not (authkey or authurl):
			return HTTPBadRequest()(environ, start_response)
		if account and (not container):
			path = req.path.replace(version,'')
			if path[-1]=='/':
				path=path[:-1]
			sql = "SELECT * FROM AuthServers WHERE File_Path=?"
			self.cursor.execute(sql , [(path)])
			q = self.cursor.fetchone()
			if not q :# if account does not exist
				self.cursor.execute("INSERT INTO AuthServers VALUES ('"
				+authurl.replace('\'','').replace('\"','')+"' , '" 
				+authkey.replace('\'','')+"' , '"
				+path.replace('\'','').replace('\"','')+ "' )")
				self.conn.commit()
				#passing the request to main app
				environ ['swift.authorize'] = self.authorize
				environ ['swift.clean_acl'] = clean_acl
				return self.app(environ, start_responce)
			else: 
				return HTTPUnauthorized()(environ,start_response)
		else: # if request refers to a container
			return HTTPUnauthorized()(environ,start_response)
			

	def PathCheck ( self,environ, start_response):
		"""
		Checks if the requested path exists and returns the preconfigured Authentication Server URL
		along with the token that has to be verified
		"""
		req = Request(environ)
		# splitting request URL in version, account,container, object
		try:
			version,account, container, obj = split_path(req.path, 1, 4, True)
			path = req.path.replace(version,'')
		except:
			return HTTPBadRequest()(environ, start_response)
		if path[-1]=='/':
			path=path[:-1]
		sql = "SELECT * FROM AuthServers WHERE File_Path=?"
		self.cursor.execute(sql , [(path)])
		q = self.cursor.fetchone()
		if not q :
			s = 'SimpleAuth: PathCheck: Path '+path+' Not Found'
			print >> environ ['wsgi.errors'], s
			return HTTPNotFound()(environ, start_response)
		try:
	
			policy =str(q[0])
		except:
			return HTTPBadRequest()(environ, start_response)

		memcache_client = cache_from_env(req.environ)
                if not memcache_client:
        	        raise Exception('Memcache required')
		# generating token
		token = uuid4().hex
		published = time()
		expires = published+ 60 # default expiration time
		memcache_token_key =  '%s/token/%s' % (self.reseller_prefix,token)
		memcache_client.set(memcache_token_key, (published, policy, False,'0'), timeout=float(expires-time()))
		# creating the message for  Access Control Provider
		message = '{"X-Auth-Token" : "'+token+'"}'
		resp = Response (request=req, headers={'x-policy-url' : policy, 'x-auth-message': message, 'x-public-key' : str(self.CloudKeys.public_key)})
		return resp(environ, start_response)           
	
			

def filter_factory(global_conf, **local_conf):
	conf = global_conf.copy()
	conf.update(local_conf)
	
	def auth_filter(app):
		return SimpleAuth(app,conf)
	return auth_filter
