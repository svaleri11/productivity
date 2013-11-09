import json, sys
import random
import string
import hashlib
from datetime import datetime
from apiclient.discovery import build

from flask import Flask
from flask import make_response
from flask import render_template
from flask import request
from flask import session
from flask import g, redirect, url_for, abort, render_template, flash

import sqlite3

import httplib2
from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from simplekv.memory import DictStore
from flaskext.kvsession import KVSessionExtension

from contextlib import closing


app = Flask(__name__)
app.config.from_object('config')
app.secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits)
                         for x in xrange(32))
APPLICATION_NAME = 'Productive'

# See the simplekv documentation for details
store = DictStore()


# This will replace the app's session handling
KVSessionExtension(store, app)


# Update client_secrets.json with your Google API project information.
# Do not change this assignment.
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
SERVICE = build('plus', 'v1')


def is_authenticated():
  # Only disconnect a connected user.
  credentials = session.get('credentials')
  google_id = session.get('google_id')
  if credentials is None or google_id is None:
    return False
    #    abort(401)


@app.route('/', methods=['GET'])
def index():
  """Initialize a session for the current user, and render index.html."""
  # Create a state token to prevent request forgery.
  # Store it in the session for later validation.
  state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                  for x in xrange(32))
  session['state'] = state

  flow = flow_from_clientsecrets('client_secrets.json',
                               scope='https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/plus.login',
                               redirect_uri='http://127.0.0.1:5000/authenticate')
  auth_uri = flow.step1_get_authorize_url()

  # Set the Client ID, Token State, and Application Name in the HTML while
  # serving it.
  response = make_response(
      render_template('index.html',
                      CLIENT_ID=CLIENT_ID,
                      STATE=state,
                      APPLICATION_NAME=APPLICATION_NAME,
                      GOOGLE_URL=auth_uri))
  response.headers['Content-Type'] = 'text/html'

  return response


@app.route('/authenticate')
def authenticate_google():
  code = request.args.get("code")
  flow = flow_from_clientsecrets('client_secrets.json',
                               scope='https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/plus.login',
                               redirect_uri='http://127.0.0.1:5000/authenticate')
  try:
    credentials = flow.step2_exchange(code)
    http = httplib2.Http()
    http = credentials.authorize(http)
    service = build('plus', 'v1', http=http)
    people_resource = service.people()
    people_document = people_resource.get(userId='me').execute()
    session['credentials'] = credentials

  except FlowExchangeError:
    response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
 
  google_id = people_document['id']
  user = query_db('select * from users where googleId = ?', [google_id], one=True)
  #If no user exists in our db, register them
  if user is None:
    print 'No user, creating'
    name = people_document['displayName']
    cur = g.db.cursor()
    cur.execute('insert into users (name, googleid) VALUES (?, ?)', [name, google_id])
    g.db.commit()
    id = cur.lastrowid
    print "user: %r" % id

  #User exists so log them in
  else:
    print "The user is %r" % user[0]

  session['google_id'] = google_id

  #Redirect to user logged in page
  return redirect(url_for('home'))

@app.route('/connect', methods=['POST'])
def connect():
  """Exchange the one-time authorization code for a token and
  store the token in the session."""
  # Ensure that the request is not a forgery and that the user sending
  # this connect request is the expected user.
  if request.args.get('state', '') != session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  # Normally, the state is a one-time token; however, in this example,
  # we want the user to be able to connect and disconnect
  # without reloading the page.  Thus, for demonstration, we don't
  # implement this best practice.
  # del session['state']

  code = request.data

  try:
    # Upgrade the authorization code into a credentials object
    oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
    oauth_flow.redirect_uri = 'postmessage'
    credentials = oauth_flow.step2_exchange(code)

  except FlowExchangeError:
    response = make_response(
        json.dumps('Failed to upgrade the authorization code.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # An ID Token is a cryptographically-signed JSON object encoded in base 64.
  # Normally, it is critical that you validate an ID Token before you use it,
  # but since you are communicating directly with Google over an
  # intermediary-free HTTPS channel and using your Client Secret to
  # authenticate yourself to Google, you can be confident that the token you
  # receive really comes from Google and is valid. If your server passes the
  # ID Token to other components of your app, it is extremely important that
  # the other components validate the token before using it.
  gplus_id = credentials.id_token['sub']

  stored_credentials = session.get('credentials')
  stored_gplus_id = session.get('gplus_id')
  if stored_credentials is not None and gplus_id == stored_gplus_id:
    response = make_response(json.dumps('Current user is already connected.'),
                             200)
    response.headers['Content-Type'] = 'application/json'
    return response

  if (credentials is not None):
    http = httplib2.Http()
    http = credentials.authorize(http)
    service2 = build('plus', 'v1', http=http)
    people_resource = service2.people()
    people_document = people_resource.get(userId='me').execute()
    print "name: " + people_document['displayName']
 

  # Store the access token in the session for later use.
  session['credentials'] = credentials
  session['gplus_id'] = gplus_id
  session['user_id'] = 1
  response = make_response(json.dumps('Successfully connected user.', 200))
  response.headers['Content-Type'] = 'application/json'
  return response

@app.route('/disconnect', methods=['GET'])
def disconnect():
  """Revoke current user's token and reset their session."""
  # Only disconnect a connected user.
  google_id = session.get('google_id')
  credentials = session.get('credentials')
  if credentials is None or google_id is None:
    response = make_response(json.dumps('Current user not connected.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Execute HTTP GET request to revoke current token.
  access_token = credentials.access_token
  url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
  h = httplib2.Http()
  result = h.request(url, 'GET')[0]

  if result['status'] == '200':
    # Reset the user's session.
    del session['credentials']
    del session['google_id']
    response = make_response(json.dumps('Successfully disconnected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    return response
  else:
    # For whatever reason, the given token was invalid.
    response = make_response(
        json.dumps('Failed to revoke token for given user.', 400))
    response.headers['Content-Type'] = 'application/json'
    return response

def connect_db():
    """Connect to the SQLite3 database"""
    return sqlite3.connect(app.config['DATABASE'])

def query_db(query, args=(), one=False):
    cur = connect_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()

#DB functions before request
@app.before_request
def before_request():
    g.db = connect_db()

#DB functions after request
@app.teardown_request
def teardown_request(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()

@app.route('/home')
def home():
    if (is_authenticated() is False):
      return redirect(url_for('index'))

    #get user name from the database or google and send it to the HTML template
    stored_credentials = session.get('credentials')

    http = httplib2.Http()
    http = stored_credentials.authorize(http)
    service = build('plus', 'v1', http=http)
    people_resource = service.people()
    people_document = people_resource.get(userId='me').execute()
    return render_template('home.html', name=people_document['displayName'])

@app.route('/activity/addForm', methods=['GET'])
def add_activity_form():
  if (is_authenticated() is False):
      return redirect(url_for('index'))

  return render_template('add-activity.html')

@app.route('/activity', methods=['POST'])
def add_activity():
  if (is_authenticated() is False):
      return redirect(url_for('index'))

  book_title = request.form['bookTitle']
  book_length = request.form['bookLength']
  time_period = request.form['timePeriod']
  print "Book title %r" % book_title

  return render_template('suggest-activity.html', book_title = book_title,
                                                  book_length = book_length,
                                                  time_period = time_period)


if __name__ == "__main__":
    app.run()