from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Car, Model, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

# Connect to database
engine = create_engine('sqlite:///carswithusers2.db')
Base.metadata.bind = engine

# Create database session
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/car/')
def showCars():
    # get all the cars
    cars = session.query(Car).order_by(asc(Car.name))
    # check if user is logged in
    if not is_user():
        return render_template('publiccars.html', cars=cars)
    else:
        return render_template('cars.html', cars=cars)


@app.route('/car/add/', methods=['GET', 'POST'])
def addCar():
    if not is_user():
        return redirect('/login')
    if request.method == 'POST':
        newCar = Car(
            name=request.form['name'], sign=request.form['sign'],
            user_id=login_session['user_id'])
        session.add(newCar)
        flash('New Car %s Successfully Added' % newCar.name)
        session.commit()
        return redirect(url_for('showCars'))
    else:
        return render_template('newCar.html')


@app.route('/car/<int:car_id>/edit/', methods=['GET', 'POST'])
def editCar(car_id):
    editedCar = session.query(Car).filter_by(id=car_id).one()
    if not is_user():
        return redirect('/login')
    if editedCar.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to\
         edit this car. Please create your own car in order to \
         edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedCar.name = request.form['name']
            flash('Car Successfully Edited %s' % editedCar.name)
            return redirect(url_for('showCars'))
    else:
        return render_template('editCar.html', car=editedCar)


@app.route('/car/<int:car_id>/delete/', methods=['GET', 'POST'])
def deleteCar(car_id):
    carToDelete = session.query(Car).filter_by(id=car_id).one()
    if not is_user():
        return redirect('/login')
    if carToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to \
        delete this car. Please create your own car in order to\
         delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(carToDelete)
        flash('%s Successfully Deleted' % carToDelete.name)
        session.commit()
        return redirect(url_for('showCars', car_id=car_id))
    else:
        return render_template('deleteCar.html', car=carToDelete)


@app.route('/car/<int:car_id>/')
@app.route('/car/<int:car_id>/model/')
def showModels(car_id):
    # get one car by id
    car = session.query(Car).filter_by(id=car_id).one()
    # get all the models from the car
    models = session.query(Model).filter_by(car_id=car_id).all()
    creator = getUserInfo(car.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']: # noqa: E501
        return render_template('publicmodels.html', models=models, car=car,
                               creator=creator)
    else:
        return render_template('models.html', models=models, car=car,
                               creator=creator)


@app.route('/car/<int:car_id>/model/add/', methods=['GET', 'POST'])
def addModel(car_id):
    if not is_user():
        return redirect('/login')
    car = session.query(Car).filter_by(id=car_id).one()
    if login_session['user_id'] != car.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
        to add models to this car. Please create your own car in order to add\
        models.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newModel = Model(name=request.form['name'],
                         price=request.form['price'],
                         car_class=request.form['car_class'],
                         electric_range=request.form['electric_range'],
                         car_id=car_id)
        session.add(newModel)
        session.commit()
        flash('New Model %s Successfully Created' % (newModel.name))
        return redirect(url_for('showModels', car_id=car_id))
    else:
        return render_template('newModel.html', car_id=car_id)


@app.route('/car/<int:car_id>/model/<int:model_id>/edit/',
           methods=['GET', 'POST'])
def editModel(car_id, model_id):
    if not is_user():
        return redirect('/login')
    editedModel = session.query(Model).filter_by(id=model_id).one()
    car = session.query(Car).filter_by(id=car_id).one()
    if login_session['user_id'] != car.user_id:
        return "<script>function myFunction() {alert('You are not authorized to\
         edit models to this car. Please create your own car in order to edit \
         models.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedModel.name = request.form['name']
        if request.form['price']:
            editedModel.price = request.form['price']
        if request.form['car_class']:
            editedModel.car_class = request.form['car_class']
        if request.form['electric_range']:
            editedModel.electric_range = request.form['electric_range']
        session.add(editedModel)
        session.commit()
        flash('Model Successfully Edited')
        return redirect(url_for('showModels', car_id=car_id))
    else:
        return render_template('editModel.html', car_id=car_id,
                               model_id=model_id, model=editedModel)


@app.route('/car/<int:car_id>/model/<int:model_id>/delete/',
           methods=['GET', 'POST'])
def deleteModel(car_id, model_id):
    if not is_user():
        return redirect('/login')
    car = session.query(Car).filter_by(id=car_id).one()
    modelToDelete = session.query(Model).filter_by(id=model_id).one()
    if login_session['user_id'] != car.user_id:
        return "<script>function myFunction() {alert('You are not authorized to\
         delete models to this car. Please create your own car in order to \
         delete models.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(modelToDelete)
        session.commit()
        flash('Model Successfully Deleted')
        return redirect(url_for('showModels', car_id=car_id))
    else:
        return render_template('deleteModel.html', model=modelToDelete)


@app.route('/login')
def showLogin():
    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/logout')
def logout():
    if login_session['provider'] == 'facebook':
        fbdisconnect()
    if login_session['provider'] == 'google':
        gdisconnect()
    return redirect(url_for('showCars'))


# Login with facebook
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % ( # noqa: E501
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"

    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token # noqa: E501
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token # noqa: E501
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
    output += ' " style = "width: 300px; height: 300px;border-radius:\
     150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    flash("you have been logged out")
    login_session.pop('username', None)
    login_session.pop('access_token', None)


# Login with google
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already \
                                            connected.'), 200)

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

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;">' # noqa: E501
    flash("you are now logged in as %s" % login_session['username'])
    return output


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
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("you have been logged out")
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for \
                                            given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


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
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def is_user():
    if 'username' in login_session:
        return True
    else:
        return False


# JSON APIs to view Cars Information
@app.route('/car/JSON')
def carsJSON():
    cars = session.query(Car).all()
    return jsonify(cars=[c.serialize for c in cars])


@app.route('/car/<int:car_id>/model/JSON')
def carModelsJSON(car_id):
    car = session.query(Car).filter_by(id=car_id).one()
    models = session.query(Model).filter_by(
        car_id=car_id).all()
    return jsonify(Model=[m.serialize for m in models])


@app.route('/car/<int:car_id>/model/<int:model_id>/JSON')
def modelsJSON(car_id, model_id):
    model = session.query(Model).filter_by(id=model_id).one()
    return jsonify(Model=model.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
