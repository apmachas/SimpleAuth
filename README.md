An Auth Service for OpenStack Object Storage (Swift) as WSGI Middleware.

	Access control delegation for the Cloud


	Installation Guide created by Apostolis Machas, on Wen Feb 19 2014. 

**Note 1: Software and Installation Guide applies to the "default" Swift architecture consisting of a single Proxy node. 
	  For more complex implementations, additional changes shall be made. 
**Note 2: This Software and Installation Guide has been created for Academic research purposes, NOT FOR COMMERCIAL USE. 
	  Software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
		
		
		Contents:
		
		1. Middleware
			1.1 Overview
			1.2 Database
			1.3 Installation
		2. Access Control Provider Installation
			2.1 Overview
			2.2 Database
			2.3 Running AuthServer.py
		3. Client
			3.1 Overview
			3.2 Running client.py
		
		
1. Middleware

	Before discussing how to install SimpleAuth within a Swift system, it might help to understand how SimpleAuth does it work first.
		
	1.1 Overview
	
		a. SimpleAuth is a middleware installed in the Swift Proxy’s WSGI pipeline.
		b. It intercepts all requests to swift's app (by default).
		c. Authentication service is performed using an external Access Control Provider. No user's Data is stored in Cloud Provider. 
		d. Authentication data required by Cloud Provider are Policy URL and Access Control Provider's Public Key, stored in a Database file described at proxy servers configuration file.
		e. In case of a non-clean installation, Database file with the additional authentication data should be provided.
		
		Please read paper "Access control delegation for the Cloud" for more detailed information.
		
	1.2 Database
	
	SimpleAuth is using a SQLite database file consisting of one Table named AuthServers.

		Table AuthServers
		-----------------------------------------
		| PolicyUrl | AuthServerKey | File_Path |
		-----------------------------------------
		
		Values:
			PolicyUrl: text
			AuthServerKey: text
			File_Path: text
			
		Primary Key: (PolicyUrl,File_Path)
		
	1.3 Installation
	
		Dependencies:
					SQLite, keyCzar, JSON, OpenStack - Object Storage (Swift)
					
		a. Install SimpleAuth with sudo python setup.py install on Swift's proxy-node.
	
		b. Alter your proxy-server.conf pipeline to use SimpleAuth: 
			! Note: Add simpleauth just before proxy-server app. 
	
			e.g.
				[pipeline:main]
				pipeline = catch_errors cache simpleauth proxy-server
		
		c. Enable SSL at proxy-server.conf:
	
			e.g.
				[DEFAULT]
				cert_file = /etc/swift/cert.crt
				key_file = /etc/swift/cert.key
				bind_port = 443
				
		d. Add to your proxy-server.conf the section for the SimpleAuth WSGI filter:
			
			Parameter DB_File: Set the database file to be used.
			If DB_File is not set, default location "/etc/swift/SimpleAuth.db" is used.
			
			e.g.			
				[filter:simpleauth]
				use = egg:myauth#simpleauth
				DB_File = /home/usr/SimpleAuth.db
		
		e. Provide administrator permissions on database file to swift user. 
			e.g. 
				#chown swift SimpleAuth.db
				
		f. Restart Swift
				# swift-init restart all
				
				
2. Access Control Provider

	2.1. Overview
		 
		 AuthServer.py is a "stand-alone" python executable, acting as Access Control Provider as described at "Access control delegation for the Cloud" paper.

	2.2 Database
	
	AuthServer.py is using a SQLite database file consisting of two Tables named Users and Policies.
	
		Table Users
		-----------------------
		| Username | Password |
		-----------------------
		
		Values:
			Username: text
			Password: text
			
		Primary Key: Username
	
	
		Table Policies
		------------------------------------------
		| Policy | Username | AccessLevel | Time |
		------------------------------------------
		
		Values:
			Policy: text
			Username: text
			AccessLevel: text
			Time: text
			
		Primary Key: (Policy,Username)
		Foreign Key: Usename References Users(Username)
		
	2.3. Running AuthServer.py
	
		Dependencies:
				SQLite, keyCzar, JSON
					
		a. Alter your AuthServer.py to use your Servers IP address, Port and Certificate files .
			
			e.g. 
				ServerHostname = '10.0.0.1'
				server_address = (ServerHostname, 443)
	            httpd.socket = ssl.wrap_socket (httpd.socket, certfile = 'cert.crt',keyfile="cert.key", server_side = True)
			 
			
		b. Create a database file named "AuthServer.db" in the same directory as AuthServer.py
				
				e.g.
				#sqlite3 AuthServer.db
				
		c. Update database file with Tables described at 2.2.
				
				e.g.
				sqlite> CREATE TABLE IF NOT EXISTS Users (Username text, Password text, PRIMARY KEY (Username));
				sqlite> CREATE TABLE IF NOT EXISTS Policies(Policy text , Username text, AccessLevel text, Time text,PRIMARY KEY (Policy, Username), FOREIGN KEY(Username) REFERENCES USERS(Username));
				
		d. Insert sample Values to Table Users
		
				e.g.
				#sqlite> INSERT INTO Users VALUES ('Username1','Password1');	
		
		e. Run AuthServer.py using python AuthServer.py 		

		
3. Client

	3.1 Overview
	
		client.py is a "stand-alone" python executable, created to simplify usage of the SSO system described at "Access control delegation for the Cloud" paper.
		It is using cURL to automate HTTP communications between user and both Cloud Provider and Access Control Provider. 

	3.2 Running client.py
	
		Dependencies:
					JSON, cURL
					
		#python client.py
		
		follow the instructions provided.
		!Note:  Cloud Provider's URLs must be in form "hostname/v1/account/container/object". 
				Always include version ("/v1/") and "/" between hostname, account etc.
		
		!Note: In case Cloud Provider and/or Access Control Provider use a different port than 443 make the appropriate changes at client.py file.

			eg.
				conn.request("GET", CloudHostfile+':4443')
