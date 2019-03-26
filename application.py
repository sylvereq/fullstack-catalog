import string
import random
from passlib.apps import custom_app_context as pwd_context
import requests
from flask import make_response
import urllib
import json
import httplib2
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from flask import session as login_session
from flask import (Flask, render_template, url_for, request,
                   redirect, flash, send_from_directory, jsonify, abort, g)
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()


app = Flask(__name__, static_url_path='')

CLIENT_SECRECTS = json.loads(open('client_secrets.json', 'r').read())['web']
APPLICATION_NAME = "Item Catalog"

engine = create_engine('sqlite:///items.db',
                       connect_args={'check_same_thread': False}, echo=False)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Convenient functions for user handling
def createUser(login_session):
    newUser = User(email=login_session['email'])
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
    except BaseException:
        return None

# Serves a cool icon :)
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(
        app.root_path, 'static'), 'favicon.ico', mimetype='image/x-icon')

# Callback for the OAuth GitHub Login
@app.route('/callback', methods=['GET', 'POST'])
def callback():
    print "Session-State: " + login_session['state']
    print "Request-State: " + request.args.get('state')
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://github.com/login/oauth/access_token'
    code = request.args.get('code')

    data = {'client_id': CLIENT_SECRECTS['client_id'],
            'client_secret': CLIENT_SECRECTS['client_secret'], 'code': code}
    body = urllib.urlencode(data)
    h = httplib2.Http()
    headers = {'Accept': 'application/json'}
    response, content = h.request(url, 'POST', body=body, headers=headers)
    print content

    token = json.loads(content)['access_token']
    access_url = 'https://api.github.com/user/emails?access_token=%s' % token

    response, apicontent = h.request(access_url, 'GET')
    print apicontent

    login_session['email'] = json.loads(apicontent)[0]['email']

    return redirect(url_for('showStart'))

# Disconnects any logged-in users
@app.route("/disconnect")
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        # check if user is connected over normal account
        if 'email' in login_session:
            login_session.pop('email', None)
            login_session.pop('username', None)
            return redirect('/login')
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

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
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Serves a login page for all known users and users via github
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# This will be called if a user creates a new category
@app.route('/newCategory', methods=['POST'])
def newCategory():
    if 'email' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        userid = getUserID(login_session['email'])
        if userid is None:
            userid = createUser(login_session)
        user = getUserInfo(userid)
        categoryExists = session.query(Category).filter_by(
            name=request.form['categoryName'], user=user).first()
        if categoryExists:
            login_session['warning'] = "Category Name already exists"
            return redirect(url_for('showStart'))
        else:
            newItem = Category(user=user, name=request.form['categoryName'])
            session.add(newItem)
            session.commit()

    return redirect(url_for('showStart'))

# This will be called if a user creates a new item
@app.route('/newItem', methods=['GET', 'POST'])
def newItem():
    if 'email' not in login_session:
        return redirect('/login')

    userid = getUserID(login_session['email'])
    user = getUserInfo(userid)
    category = session.query(Category).filter_by(
        name=request.form['categoryName'], user_id=userid).one()
    newItem = Item(
        user=user,
        category=category,
        title=request.form['itemTitle'],
        description=request.form['itemDesc'],
        imgSource=request.form['itemImg'])
    session.add(newItem)
    session.commit()

    return redirect(url_for('showStartWithCategory',
                            categoryName=category.name))

# This will be called if a user deletes a item :(
@app.route('/deleteItem', methods=['GET', 'POST'])
def deleteItem():
    if 'email' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        item = session.query(Item).filter_by(id=request.form['cardid']).one()
        session.delete(item)
        session.commit()

    return redirect(url_for('showStartWithCategory',
                            categoryName=request.form['categoryName']))

# This will be called if a user deletes a item :(
@app.route('/updateItem', methods=['GET', 'POST'])
def updateItem():
    if request.method == 'GET':
        print(request.data)

    item = session.query(Item).filter_by(id=request.form['cardid']).one()
    item.title = request.form['itemTitle']
    item.description = request.form['itemDescription']
    session.add(item)
    session.commit()

    return redirect(url_for("showStartWithCategory",
                            categoryName=request.form['categoryName']))

# Starting point of the user after the login
@app.route('/', methods=['GET', 'POST'])
def showStart():
    if 'email' not in login_session:
        return redirect('/login')

    userid = getUserID(login_session['email'])
    categories = session.query(Category).filter_by(user_id=userid).all()

    if len(categories) == 0:
        message = "<< Please create a new category"
    else:
        message = "<< Please select or create a new category"

    creatorMail = login_session['email']
    return render_template(
        'start.html',
        categories=categories,
        creatorMail=creatorMail,
        message=message)

# Will highlight a category and shows their items after user selects one
@app.route('/<categoryName>')
def showStartWithCategory(categoryName):
    if 'email' not in login_session:
        return redirect('/login')

    userid = getUserID(login_session['email'])
    categoryItem = session.query(Category).filter_by(name=categoryName,
                                                     user_id=userid).one()
    items = session.query(Item).filter_by(
        category=categoryItem, user_id=userid).all()
    categories = session.query(Category).filter_by(user_id=userid).all()
    creatorMail = login_session['email']
    return render_template(
        'selectedCategory.html',
        categories=categories,
        categoryName=categoryName,
        items=items,
        creatorMail=creatorMail)


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@auth.verify_password
def verify_password(email_or_token, password):
    user_id = User.verify_auth_token(email_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).first()
    else:
        user = session.query(User).filter_by(email=email_or_token).first()
        if not user or not user.check_pw(password):
            return False
    g.user = user
    return True

# API to get all the users
@app.route('/api/users', methods=['POST', 'GET'])
@auth.login_required
def new_user():
    password = request.json.get('password')
    username = request.json.get('email')
    if username is None or password is None:
        abort(400)  # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)  # existing user
    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({'username': user.username}), 201, {
        'Location': url_for('get_user', id=user.id, _external=True)}


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
