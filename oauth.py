import web
import os
import urllib2, httplib
import json 
from sanction import Client

from StringIO import StringIO


web.config.debug = False

CLIENT_ID = os.environ.get('CLIENT_ID', '') 
CLIENT_SECRET = os.environ.get('CLIENT_SECRET', '') 
SERVER_URL = os.environ.get('SERVER_URL', '') + "/oauth-redirect"
RALLY_WSAPI_URL = "rally1.rallydev.com"
RALLY_USER_URL = "/slm/webservice/v2.x/user"

print CLIENT_ID
print CLIENT_SECRET
print SERVER_URL

try:
	c = Client(auth_endpoint = "https://rally1.rallydev.com/login/oauth2/auth",
			token_endpoint = "https://rally1.rallydev.com/login/oauth2/token",
			client_id = CLIENT_ID,
			client_secret = CLIENT_SECRET)

except Exception, e:
	print "Failed to init the OAuth2 Client " + str(e)
	exit(0)


urls = (
	'/', 'display_stories',
	'/login', 'login',
	'/logout', 'logout',
	'/oauth-redirect', 'redirect' 
)

app = web.application(urls, globals())
session = web.session.Session(app, web.session.DiskStore('sessions'), initializer={'access_token' : None})

class display_stories:
	def GET(self, *args, **kwargs):
		print "Session is ", session, " -- ", session.keys(), " -- ", session.values()
		if not session.get("access_token"):
			raise web.seeother('/login')
		
		conn = httplib.HTTPSConnection(RALLY_WSAPI_URL)
		conn.connect()
		conn.request("GET", RALLY_USER_URL, headers = { "zsessionid" : session["access_token"] })
		user_resp = json.loads(conn.getresponse().read())
		print "User Resp ", user_resp
		return "Hello ", user_resp["User"]["UserName"] 

class login:
	def GET(self, *args, **kwargs):
		print "Login ", kwargs, " args ", args, " -- ", web.seeother(c.auth_uri(redirect_uri = SERVER_URL, scope="openid"))
		raise web.seeother(c.auth_uri(redirect_uri = SERVER_URL, scope="openid"))

class logout:
	def GET(self, *args, **kwargs):
		return "Logout"

class redirect:
	def GET(self, *args, **kwargs):
		code = web.input( code = '')["code"]
		try:
			access_token = c.request_token( redirect_uri = SERVER_URL, code = code )
		except urllib2.HTTPError, e:
			raise e
		session.access_token = c.access_token
		print "Session ", session.keys(), " -- ", session.values(), " -- ", session.get("access_token"), " -- ", c.access_token, " access ", access_token
		print "Try this ", session.access_token
		raise web.seeother('/')


if __name__ == "__main__":
	app.run()
