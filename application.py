from flask import Flask, render_template, url_for, request, redirect, flash, jsonify, abort, g
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

from passlib.apps import custom_app_context as pwd_context

app = Flask(__name__, static_url_path='')

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Udacity Fullstack Project"

engine = create_engine('sqlite:///items.db', connect_args={'check_same_thread': False}, echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/nlogin', methods=['POST'])
def nlogin():
    if request.method == 'POST':
        pw = request.form['password']
        email = request.form['email']
        print("PW: "+pw +str(len(pw))+" Email: "+email)

        if len(pw) is 0 or len(email) is 0:
            return redirect('/')

        user = session.query(User).filter_by(email=email).first()
        if user or user.check_pw(pw):
            login_session['username'] = user.name
            login_session['email'] = user.email
            return redirect('/')
        return redirect('/nlogin')
    return redirect('/nlogin')

@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='', redirect_uri='postmessage')
        """oauth_flow.redirect_uri = 'postmessage'"""
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(
        json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v2/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    print(credentials.access_token)
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    print(answer)

    data = answer.json()
    print(data)
    login_session['username'] = data['name']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

@app.route("/disconnect")
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        #check if user is connected over normal account
        if 'email' in login_session:
            login_session.pop('email', None)
            login_session.pop('username', None)
            return redirect('/login')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state

    return render_template('login.html', STATE=state)


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

@app.route('/newCategory', methods=['GET','POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Category(name = request.form['categoryName'])
        session.add(newItem)
        session.commit()

    return redirect(url_for('showStart'))

@app.route('/newItem', methods=['GET','POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Item(title = request.form['itemTitle'], description = request.form['itemDesc'], imgSource = request.form['itemImg'] )
        session.add(newItem)
        session.commit()

    return redirect(url_for('showStart'))

def deleteItem():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Category(name = request.form['itemName'])
        session.add(newItem)
        session.commit()

    return redirect(url_for('showStart'))

@app.route('/')
def showStart():
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    items = session.query(Item).all()
    creatorMail = login_session['email']
    return render_template('start.html', categories=categories, items=items, creatorMail=creatorMail)

@app.route('/<string:categoryName>')
def showStartWithCategory(categoryName):
    
    categoryItem = session.query(Category).filter_by(name=categoryName)
    items = session.query(Item).filter_by(category=categoryItem).all()

    return render_template('start.html', categories=categories, items=items, creatorMail=creatorMail)


###### API #####

@app.route('/token')
@auth.login_required
def get_auth_token():
     token = g.user.generate_auth_token()
     return jsonify({'token': token.decode('ascii')})

@auth.verify_password
def verify_password(email_or_token, password):
    print(email_or_token + " " + password)
    user_id = User.verify_auth_token(email_or_token)
    if user_id:
        user = session.query(User).filter_by(id = user_id).first()
    else:
        user = session.query(User).filter_by(email = email_or_token).first()
        if not user or not user.check_pw(password):
            return False
    g.user = user
    return True  

@app.route('/api/users', methods=['POST','GET'])
@auth.login_required
def new_user():
    password = request.json.get('password')
    username = request.json.get('email')
    if username is None or password is None:
        abort(400) # missing arguments
    if User.query.filter_by(username = username).first() is not None:
        abort(400) # existing user
    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({ 'username': user.username }), 201, {'Location': url_for('get_user', id = user.id, _external = True)}
   

@app.route('/api', methods=['GET', 'POST'])
def serveAPI():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'GET':
        return jsonify(success=True)


if __name__ == '__main__':
    app.secret_key = os.urandom(24)
    app.debug = True
    app.run(host='0.0.0.0', port=5000)