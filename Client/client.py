# Author: Machas Apostolos
# E-mail: ap.machas@gmail.com, a.machas@dias.aueb.gr

# Software is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.


#! /usr/bin/python
import httplib, urllib
import os
import json
def run():
	flag = True
	while flag :
		print ('[Select Operation Category]')
		op = raw_input('\n1. ACP Operations \n2. Cloud Provider Operations\n3. Exit\n')
		os.system('clear')
		if op == '1':
			AcpOp()
		elif op == '2':
			CloudOp()
		elif op == '3' :
			flag = False

def AcpOp():
	flag = True
	while flag :
		print ('[Select Operation]')
		op = raw_input('\n1. Create Policy \n2. Update Policy\n3. Back To Main Menu\n')
		os.system('clear')
		if op == '3':
			break
		if op == '1' or op == '2':
			Username = raw_input('Enter your Username:')
			Password = raw_input('Enter your Password:')
			Policy = raw_input('Enter the Policy URL to Create/Update:')
			Time = raw_input('Access Time:')
			if op =='1' :
				command = "curl -X PUT -k -v -H 'X-Auth-User: "+ Username+" ' -H 'X-Auth-Pass: "+Password+"' -H 'X-Time: "+Time+"' https://"+Policy
				os.system(command)
			elif op =='2' :
				User = raw_input('Enter the User you want to add to this policy:')
				AccLvl = raw_input ('Enter the Access Level for the new user:')
				command = "curl -X PUT -k -v -H 'X-Auth-User: "+ Username+" ' -H 'X-Auth-Pass: "+Password+" ' -H 'X-User: "+User+" ' -H 'X-Access-Level: "+AccLvl+"' -H 'X-Time: "+Time+"' https://"+Policy
				os.system(command)

def CloudOp():
	token = None
	while True :
		print ('[Select Operation]')
		op = raw_input('\n1. Create Account \n2. Create Container/Object \n3. GET/DELETE/POST/... \n4. Copy Object \n5. Reset Token \n6. Back To Main Menu \n')
		os.system('clear')
		if op == '6':
			break
		elif op =='5':
			token = None	
			print "Security-Token reset! \n"
		elif op == '1':
			CloudHostName = raw_input('Enter the Cloud Hostname:')
			CloudHostfile = raw_input('Enter the Account name:')
			ACPHostName = raw_input('Enter the ACP Hostname :')
			Policy = raw_input('Enter the Policy Url :')
			print '[Contacting the ACP...]'
			conn = httplib.HTTPSConnection(ACPHostName)
			conn.request("GET", Policy)
			response = conn.getresponse()
			print response.status, response.reason
			if response.status == 200 :
				PolicyUrl = response.getheader('X-Policy-Url')
				ACPPK = response.getheader('X-Public-Key')
				command = "curl -X PUT -k -v -H 'X-Policy-Url: "+PolicyUrl+"' -H 'X-Public-Key: "+ACPPK+"' https://"+CloudHostName+CloudHostfile
				os.system(command)
		else:
			
			if not token : 
				Username =raw_input('Enter your Username:')
				Password =raw_input('Enter your Password:')
				CloudHostName = raw_input('Enter the Cloud Hostname:')
			else :
				print "Using the previous Token and Cloud Hostname. Reset Token to change Cloud Hostname and request a new one!"
			NewFile=''
			if op == '2':
				CloudHostfile = raw_input('Enter the Destination Account/Container Url (e.g. /v1/account/):')
				NewFile = raw_input('Enter the New Container/Object name (e.g. container):')
			if op == '4':
				CloudHostfile = raw_input('Enter the Destination Container Url (e.g. /v1/account/container/):')
				NewFile = raw_input('Enter the Destination Object name (e.g. object):')
				Source = raw_input('Enter the Object to Copy (e.g. /container/object):')
			elif op == '3':
				CloudHostfile = raw_input('Enter the File Url:')
			if not token:
				print '[Contacting Cloud Provider...]'
				conn = httplib.HTTPSConnection(CloudHostName)
				conn.request("GET", CloudHostfile+NewFile)
				response = conn.getresponse()
				if (op == '2' or op == '4') and not (response.status == 200) :
					conn = httplib.HTTPSConnection(CloudHostName)
					conn.request("GET", CloudHostfile)
					response = conn.getresponse()
				print response.status, response.reason
				if response.status == 200 :
					AuthMessage = response.getheader('X-Auth-Message')
					PolicyUrl = response.getheader('X-Policy-Url')
					Signature = response.getheader('X-Signature')
					CloudPK = response.getheader('X-Public-Key')
					ACPHostName,Policy =PolicyUrl.split('/',1)
					headers = {"X-Auth-User" : Username, "X-Auth-Pass" : Password, "X-Auth-Message" : AuthMessage, "X-Signature" : Signature, "X-Public-Key" : CloudPK}
					print '[Contacting ACP...]'
					conn = httplib.HTTPSConnection(ACPHostName)
					conn.request("GET", '/'+Policy,"",headers)
					response = conn.getresponse()
					print response.status, response.reason
					if response.status == 200 :
						AuthMessage = response.getheader('X-Auth-Message')
						try:
							token = '{"X-Auth-Token" : "'+json.loads(AuthMessage).get('X-Auth-Token')+'"}'
						except:
							#in case we get an invalid authmsg
							print 'Token not found! Please try again!'
							return 0
						Signature = response.getheader('X-Signature')
			else:
				AuthMessage = token
					
			if op == '2':
				print '[New File Protection]'
				ACPHostName = raw_input('Enter the ACP Hostname :')
				Policy = raw_input('Enter the Policy Url :')
				print '[Contacting the ACP...]'
				conn = httplib.HTTPSConnection(ACPHostName)
				conn.request("GET", Policy)
				response = conn.getresponse()
				print response.status, response.reason
				if response.status == 200 :					
					PolicyUrl = response.getheader('X-Policy-Url')
					ACPPK = response.getheader('X-Public-Key')
					params = raw_input ('Insert any cURL extra params (Authentication Data and Request Method will be entered automatically):')
					command = "curl -X PUT -k -v -H 'X-Policy-Url: "+PolicyUrl+"' -H 'X-Public-Key: "+ACPPK+"' -H 'X-Auth-Message: "+AuthMessage+"' -H 'X-Signature: "+Signature+"' https://"+CloudHostName+CloudHostfile+NewFile+" "+params
					os.system(command)
			elif op == '3':
				params = raw_input ('Insert any cURL extra params (Authentication Data will be entered automatically) \n**Note: For File Upload use "-X PUT --upload-file file"** \n:')
				command = "curl -k -v -H 'X-Auth-Message: "+ AuthMessage+" ' -H 'X-Signature: "+Signature+"' https://"+CloudHostName+CloudHostfile+" "+params
				os.system(command)
			elif op == '4':
				command = "curl -X PUT -k -v -H 'Content-Length: 0' -H 'X-Auth-Message: "+ AuthMessage+" ' -H 'X-Signature: "+Signature+" ' -H 'X-Copy-From: "+Source+"' https://"+CloudHostName+CloudHostfile+NewFile
				os.system(command)
if __name__ == '__main__':
	run()
