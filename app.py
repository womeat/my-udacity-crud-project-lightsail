from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash, g
from flask import make_response
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Place, Taco, User

import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json

import requests
from functools import wraps
auth = HTTPBasicAuth()

app = Flask(__name__)

# App config.
app.debug = True
app.config.from_object(__name__)
CLIENT_ID = json.loads(
    open('/home/grader/my-udacity-crud-project/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Best Tacos"
app.config['SECRET_KEY'] = '234VRU73H2487NVNVKLRTR54'

# Connect to Database and create database session
engine = create_engine('postgres://besttacos:XXXXX@localhost:5432/besttacos')
#engine = create_engine('sqlite:///best_tacos.db',
#                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# This method does the password validation
@auth.verify_password
def verify_password(username_or_token, password):
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(email=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


# Decorator to request the login
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'access_token' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('showLogin'))
    return wrap


def start_session(username, password):
    print('checking credentials for: %s', username)
    if verify_password(username, password):
        token = g.user.generate_auth_token()
        state = ''.join(random.choice(string.ascii_uppercase +
                        string.digits) for x in range(32))
        login_session['access_token'] = token
        # Get user info
        login_session['username'] = username
        login_session['email'] = username
        login_session['state'] = state
        login_session['provider'] = 'local'
        userConnected = session.query(User).filter_by(
                                email=username).one()
        login_session['user_id'] = userConnected.id
        return True
    else:
        return False


@app.route('/login-credentials', methods=['GET', 'POST'])
def login_credentials():
    if (
            request.form['username'] is not None and
            request.form['pass'] is not None
    ):
        if start_session(request.form['username'], request.form['pass']):
            return redirect(url_for('showPlaces'))
        else:
            state = ''
            flash("Wrong credentials.")
            return render_template('login.html', STATE=state)


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Creates a new user
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirmPassword = request.form['confirm-password']
        if not email or not password or not confirmPassword:
            flash("Incomplete parameters")
            return redirect(url_for('register'))
        if password != confirmPassword:
            flash("Password mismatch")
            return redirect(url_for('register'))

        if session.query(User).filter_by(email=email).first() is not None:
            flash("Existing user, please login")
            user = session.query(User).filter_by(email=email).first()
            return redirect(url_for('login_credentials'))

        user = User(email=email, name=name)
        user.hash_password(password)
        session.add(user)
        session.commit()
        flash("Account created successfuly")
        if start_session(email, password):
            return redirect(url_for('showPlaces'))
        else:
            flash("There was a problem please conntact the administrator")
            return redirect(url_for('showPlaces'))
    else:
        return render_template('register.html')


# Disconnects when provider is G+
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
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
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
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        print('*************************** NEW USER ****************')
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;'
    output += 'border-radius: 150px;-webkit-border-radius: 150px;'
    output += '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output


# Connects using the FB provider
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s ") % access_token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token'
    url += '?grant_type=fb_exchange_token&'
    url += 'client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    '''
        Due to the formatting for the result from the server
        token exchange we have to split the token first on commas
        and select the first index which gives us the key : value
        for the server access token then we split it on colons to
        pull out the actual token value and replace the remaining
        quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?'
    url += 'access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?'
    url += 'access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;'
    output += 'border-radius: 150px;-webkit-border-radius: 150px;'
    output += '-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com'
    url += '/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    print(result)
    del login_session['username']
    del login_session['picture']
    del login_session['user_id']
    del login_session['access_token']
    del login_session['provider']
    del login_session['facebook_id']
    del login_session['email']
    return "you have been logged out"


# User Helper Functions
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
    user = session.query(User).filter_by(email=email).one()
    return user.id


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    print(login_session)
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        elif login_session['provider'] == 'facebook':
            print('Disconnecting from FB')
            fbdisconnect()
        login_session.clear()
        flash("You have successfully been logged out.")
        return redirect(url_for('showPlaces'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showPlaces'))


# JSON APIs to view all Place
@app.route('/places/JSON')
@auth.login_required
def placesJSON():
    places = session.query(Place).all()
    return jsonify(Places=[i.serialize for i in places])


# JSON APIs to view all Users
@app.route('/users/JSON')
@auth.login_required
def usersJSON():
    users = session.query(User).all()
    return jsonify(Users=[i.serialize for i in users])


# JSON APIs to view a Specific Place
@app.route('/places/<int:place_id>/JSON')
@auth.login_required
def placeJSON(place_id):
    place = session.query(Place).filter_by(id=place_id).one()
    return jsonify(place.serialize)


# JSON APIs to view Tacos by Place
@app.route('/places/<int:place_id>/tacos/JSON')
@auth.login_required
def placeTacosJSON(place_id):
    tacos = session.query(Taco).filter_by(place_id=place_id).all()
    return jsonify(Tacos=[i.serialize for i in tacos])


# Main page
@app.route('/')
@app.route('/places/')
def showPlaces():
    places = session.query(Place).order_by(asc(Place.name))
    if 'username' not in login_session:
        return render_template('places.html', places=places)
    else:
        return render_template('places.html', places=places,
                               username=login_session['username'],
                               user_id=login_session['user_id'])


@app.route('/places/<int:place_id>/edit', methods=['GET', 'POST'])
@login_required
def editPlace(place_id):
    editedPlace = session.query(
        Place).filter_by(id=place_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedPlace.user_id != login_session['user_id']:
        flash("You are not authorized to edit this Place, \
            please create your own restaurant in order to edit.")
        return redirect(url_for('showPlaces'))
    if request.method == 'POST':
        if request.form['name']:
            editedPlace.name = request.form['name']
            editedPlace.picture = request.form['urlpic']
            if request.form['rate']:
                print(request.form['rate'])
                editedPlace.rate_id = request.form['rate']
            else:
                editedPlace.rate_id = 1
            session.add(editedPlace)
            session.commit()
            flash('Place Successfully Edited "%s"' % editedPlace.name)
            return redirect(url_for('showPlaces'))
    else:
        return render_template('protected/editPlace.html',
                               place=editedPlace,
                               username=login_session['username'])


# Creates a new place
@app.route('/places/new/', methods=['GET', 'POST'])
@login_required
def newPlace():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newPlace = Place(
            name=request.form['name'],
            picture=request.form['urlpic'],
            user_id=login_session['user_id'])
        if request.form['rate']:
            newPlace.rate_id = request.form['rate']
        else:
            newPlace.rate_id = 1
        session.add(newPlace)
        flash('New Place "%s" Successfully Created' % newPlace.name)
        session.commit()
        return redirect(url_for('showPlaces'))
    else:
        return render_template('protected/newPlace.html',
                               username=login_session['username'])


# Deletes a place
@app.route('/place/<int:place_id>/delete', methods=['GET', 'POST'])
@login_required
def deletePlace(place_id):
    if 'username' not in login_session:
        return redirect('/login')
    place = session.query(Place).filter_by(id=place_id).one()
    if place.user_id != login_session['user_id']:
        flash("You are not authorized to delete this Place")
        return redirect(url_for('showPlaces'))
    else:
        if request.method == 'POST':
            session.delete(place)
            session.commit()
            flash("Place deleted")
            return redirect(url_for('showPlaces'))
        else:
            return render_template('protected/deletePlace.html',
                                   place=place,
                                   username=login_session['username'])


# Deletes a taco
@app.route('/place/<int:place_id>/tacos/<int:taco_id>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteTaco(place_id, taco_id):
    if 'username' not in login_session:
        return redirect('/login')
    place = session.query(Place).filter_by(id=place_id).one()
    taco = session.query(Taco).filter_by(place_id=place_id, id=taco_id).one()
    if taco.user_id != login_session['user_id']:
        flash("You are not authorized to delete this Taco")
        return redirect(url_for('showTacos', place_id=place_id))
    else:
        if request.method == 'POST':
            session.delete(taco)
            session.commit()
            flash("Taco deleted")
            return redirect(url_for('showTacos', place_id=place_id))
        else:
            return render_template('protected/deleteTaco.html',
                                   place=place,
                                   taco=taco,
                                   username=login_session['username'])


# Edits a taco
@app.route('/place/<int:place_id>/tacos/<int:taco_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editTaco(place_id, taco_id):
    if 'username' not in login_session:
        return redirect('/login')
    place = session.query(Place).filter_by(id=place_id).one()
    tacoEdited = session.query(Taco).filter_by(place_id=place_id,
                                               id=taco_id).one()
    if tacoEdited.user_id != login_session['user_id']:
        flash("You are not authorized to edit this Taco")
        return redirect(url_for('showTacos', place_id=place_id))
    else:
        if request.method == 'POST':
            tacoEdited.name = request.form['name']
            tacoEdited.description = request.form['description']
            tacoEdited.price = request.form['price']
            tacoEdited.picture = request.form['urlpic']
            session.add(tacoEdited)
            session.commit()
            flash("Taco updated")
            return redirect(url_for('showTacos', place_id=place_id))
        else:
            return render_template('protected/editTaco.html',
                                   place=place,
                                   taco=tacoEdited,
                                   username=login_session['username'])


# Show the list of tacos
@app.route('/places/<int:place_id>/')
@app.route('/places/<int:place_id>/tacos/')
def showTacos(place_id):
    place = session.query(Place).filter_by(id=place_id).one()
    items = session.query(Taco).filter_by(
        place_id=place_id).all()
    creator = getUserInfo(place.user_id)
    if 'username' not in login_session:
        return render_template('tacosplace.html',
                               items=items,
                               place=place,
                               creator=creator)
    else:
        return render_template('tacosplace.html',
                               items=items,
                               place=place,
                               creator=creator,
                               user_id=login_session['user_id'],
                               username=login_session['username'])


# Creates a new taco
@app.route('/place/<int:place_id>/tacos/new', methods=['GET', 'POST'])
@login_required
def newTaco(place_id):
    if 'username' not in login_session:
        return redirect('/login')
    place = session.query(Place).filter_by(id=place_id).one()
    if login_session['user_id'] != place.user_id:
        flash('You are not \
            authorized to add tacos to this place. Please create\
            your own restaurant in order to add tacos.')
        return redirect(url_for('showTacos', place_id=place_id))
    if request.method == 'POST':
        taco = Taco(name=request.form['name'],
                    description=request.form['description'],
                    price=request.form['price'],
                    meat_type_id=request.form['meatTypeName'],
                    place_id=place_id,
                    user_id=place.user_id,
                    picture=request.form['picture'])
        session.add(taco)
        session.commit()
        flash('New Taco %s  Successfully Created' % (taco.name))
        return redirect(url_for('showTacos', place_id=place_id))
    else:
        return render_template('protected/newTaco.html',
                               place=place,
                               username=login_session['username'])


if __name__ == "__main__":
    app.run()
