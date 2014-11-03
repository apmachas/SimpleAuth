# Author: Machas Apostolos
# E-mail: ap.machas@gmail.com, a.machas@dias.aueb.gr

# Software is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

from setuptools import setup

setup(
	name = 'MyAuth',
	version = '1.0',
	author = 'Machas Apostolos',
	author_email = 'ap.machas@gmail.com',
	packages = ['simpleauth' , 'simpleauth.test'],
	url = '',
	license = 'LICENCE.txt',
	description = 'Authentication Middleware for Openstack-Swift',
	long_description = open ('README.txt').read(),
	install_requires=[], # removed for better compat
	entry_points={
		'paste.filter_factory':[
			'simpleauth=simpleauth.simpleauth:filter_factory',
			],
		},
)
