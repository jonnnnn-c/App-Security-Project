# NON-VULNERABLE 17/08/2020 0115
# Last updated by: Laraine

# Added rate limiting to all routes. Each route has a rate limit of 30 requests/minute and 1 request/second
# Randomized all IDs (customer, staff and product) for mass assignment
# Added ssl_context='adhoc' in app.run() to convert from http to https
# Made some changes to uptodate.py

import os
import re
import bcrypt
import pyotp
import random
from pagination import Pagination

from flask import Flask, jsonify, request, send_file, url_for, render_template, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, \
    jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
from flask_mail import Mail, Message
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from twilio.rest import Client
from flask_limiter import Limiter
from flask_talisman import Talisman

# up to date stuff
from apscheduler.schedulers.background import BackgroundScheduler
from etc.settings import uptodate
import sys
import subprocess
import atexit

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config.from_object('config.ProductionConfig')  # import config settings

blacklist = set()
db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)
mail = Mail(app)
Talisman(app)

# Twilio/SMS config

account_sid = app.config['TWILIO_ACCOUNT_SID']
auth_token = app.config['TWILIO_AUTH_TOKEN']
client = Client(account_sid, auth_token)
totp = pyotp.TOTP(app.config['PYOTP'])

# Keeping packages up to date without vulnerabilities
if uptodate.report('true') is not True:
    subprocess.call([sys.executable, os.path.abspath(__file__)])


def check_package():
    uptodate.report('false')


scheduler = BackgroundScheduler()
scheduler.add_job(func=check_package, trigger="interval", seconds=86400)  # checks for updates after 1 day
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

# Limit the number of requests
limiter = Limiter(
    app,
    default_limits=["30 per minute", "1 per second"],
)


# Customer rate limiting error message
@app.errorhandler(429)
def ratelimit_handler(e):
    return make_response(
        jsonify(message="Rate limit has exceeded %s" % e.description)
        , 429
    )


# ====================================================
SELF = "'self'"
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': SELF,
        'img-src': '*',
        'script-src': [
            SELF,
            'some.cdn.com',
        ],
        'style-src': [
            SELF,
            'another.cdn.com',
        ],
    },
    content_security_policy_nonce_in=['script-src'],
    feature_policy={
        'geolocation': '\'none\'',
    }
)

@app.after_request
def set_response_headers(response):
    response.headers['Cache-Control'] = "no-cache, no-store, must-revalidate"
    response.headers['Pragma'] = "no-cache"
    response.headers['Expires'] = '0'

    return response


@app.route('/', methods=['GET', 'POST'])
def homepage():
    return render_template('test.html')


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


@app.cli.command('update')
def update():
    return


@app.cli.command('db_reset')
def db_reset():
    db.drop_all()
    print('Database Dropped!\n')

    db.create_all()
    print('Database Created!\n')

    shirt_example = "shirt"
    for i in range(1000):
        shirt_name = shirt_example + str(i)
        sample = Product(product_name=shirt_name,
                         product_category="Men's Tops",
                         product_price=20.00,
                         product_description="example of a shirt description",
                         size_XS=600,
                         size_S=800,
                         size_M=200,
                         size_L=300,
                         size_XL=500
                         )
        db.session.add(sample)

    top_a = Product(product_name="Men Biomotion Thermo Tee",
                    product_category="Men's Tops",
                    product_price=29.90,
                    product_description="Black, Polyester Fabric",
                    size_XS=600,
                    size_S=800,
                    size_M=200,
                    size_L=300,
                    size_XL=116)

    bottom_a = Product(product_name="Men Ignite Blocked Shorts",
                       product_category="Men's Bottoms",
                       product_price=19.90,
                       product_description="Black, Polyester Fabric",
                       size_XS=101,
                       size_S=64,
                       size_M=179,
                       size_L=88,
                       size_XL=73)

    shoe_a = Product(product_name="Women Choprock Hiking Shoes",
                     product_category="Women's Shoes",
                     product_price=85.00,
                     product_description="Blue Smoke, Water-friendly synthetic and mesh upper",
                     size_XS=48,
                     size_S=36,
                     size_M=30,
                     size_L=181,
                     size_XL=62)

    accessory_a = Product(product_name="Unisex Performance Bottle",
                          product_category="Accessories",
                          product_price=15.00,
                          product_description="Transparent Carbon S18, 100% Polyethene Injection Moulded",
                          size_XS=62,
                          size_S=98,
                          size_M=103,
                          size_L=134,
                          size_XL=54)

    db.session.add(top_a)
    db.session.add(bottom_a)
    db.session.add(shoe_a)
    db.session.add(accessory_a)

    staff3 = Staff(staff_fname="Eden",
                   staff_lname="Estes",
                   staff_email="eden@business.com",
                   staff_gender="Male",
                   staff_phone=84937823,
                   staff_position="CEO",  # Root Access
                   staff_password=b"$2b$12$pTKJJxwgRDFdggqukaEsP.kNNFeg6W.QzT.eVoeSDT6qn1TeALWuK",  # B&zeden123
                   login_tries=0)

    db.session.add(staff3)

    db.session.commit()
    print('Database Seeded!')


# Pagination
Pagination()
pagination = Pagination(app, db)


# ================================== PRODUCT ==================================

@app.route('/products')
@jwt_required
@limiter.limit('default_limits')
def products():
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:

        '''
        if check_last_active(
                login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes --> CHANGE TO 10 SECONDS FOR PRESENTATION
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO" or staff.staff_position == "Product Manager":
                products_list = Product.query.all()
                result = products_schema.dump(products_list)

                # Update login user "last_active" value
                login_staff.last_active = datetime.today()
                db.session.commit()

                return jsonify(message="Products retrieved", data=result)

            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/product_details/<int:product_id>')
@jwt_required
@limiter.limit('default_limits')
def product_details(product_id: int):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO" or staff.staff_position == "Product Manager":
                product = Product.query.filter_by(product_id=product_id).first()
                if product:
                    result = product_schema.dump(product)

                    # Update login user "last_active" value
                    login_staff.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="Product retrieved", data=result)
                else:
                    return jsonify(message="Product does not exist"), 404

            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/add_product', methods=['POST'])
@jwt_required
@limiter.limit('default_limits')
def add_product():
    req_data = request.get_json()

    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO" or staff.staff_position == "Product Manager":

                product_name = req_data['product_name']  # need put validation e.g. vulnerable to injection
                if product_name == "":
                    return jsonify(message="Field required"), 409

                test = Product.query.filter_by(product_name=product_name).first()
                if test:
                    return jsonify(message="Product name exists"), 409
                else:
                    # Product ID (Randomized)
                    while True:
                        product_id = random.randint(1, 9999)
                        print("ID", product_id, "generated")

                        id_exists = Product.query.filter_by(product_id=product_id).first()
                        if id_exists:
                            print("ID", product_id, "already exists")
                        else:
                            print("New product ID is", product_id)
                            break

                    # Category
                    category = {1: "Men's Top", 2: "Men's Bottom", 3: "Men's Shoes", 4: "Men's Accessories",
                                5: "Women's Top", 6: "Women's Bottom", 7: "Women's Shoes", 8: "Women's Accessories"}
                    try:
                        product_category = int(req_data['product_category'])
                        if product_category == "":
                            return jsonify(message="Field required"), 409
                        elif product_category not in category:
                            return jsonify(message="Product category does not exist"), 409

                    except ValueError:
                        return jsonify(message="Product category does not exist"), 409

                    # Price
                    try:
                        product_price = float(req_data['product_price'])
                        if product_price == "":
                            return jsonify(message="Field required"), 409
                        elif product_price < 1:
                            return jsonify(message="Invalid price"), 409
                    except ValueError:
                        return jsonify(message="Invalid price"), 409

                    # Description
                    product_description = req_data['product_description']

                    # Size XS
                    try:
                        size_XS = int(req_data['size_XS'])
                        if size_XS == "":
                            return jsonify(message="Field required"), 409
                        elif size_XS < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    # Size S
                    try:
                        size_S = int(req_data['size_S'])
                        if size_S == "":
                            return jsonify(message="Field required"), 409
                        elif size_S < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    # Size M
                    try:
                        size_M = int(req_data['size_M'])
                        if size_M == "":
                            return jsonify(message="Field required"), 409
                        elif size_M < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    # Size L
                    try:
                        size_L = int(req_data['size_L'])
                        if size_L == "":
                            return jsonify(message="Field required"), 409
                        elif size_L < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    # Size XL
                    try:
                        size_XL = int(req_data['size_XL'])
                        if size_XL == "":
                            return jsonify(message="Field required"), 409
                        elif size_XL < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    new_product = Product(product_id=product_id,
                                          product_name=product_name,
                                          product_category=category[product_category],
                                          product_price=product_price,
                                          product_description=product_description,
                                          size_XS=size_XS,
                                          size_S=size_S,
                                          size_M=size_M,
                                          size_L=size_L,
                                          size_XL=size_XL)

                    db.session.add(new_product)
                    result = product_schema.dump(new_product)

                    # Update login user "last_active" value
                    login_staff.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="Product added", data=result), 200
            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/update_product', methods=['PUT'])
@jwt_required
@limiter.limit('default_limits')
def update_product():
    req_data = request.get_json()

    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO" or staff.staff_position == "Product Manager":
                try:
                    product_id = int(req_data['product_id'])
                    if product_id == "":
                        return jsonify(message="Field required"), 409
                except ValueError:
                    return jsonify(message="Invalid product ID"), 409

                product = Product.query.filter_by(product_id=product_id).first()
                if product:
                    # Name
                    product.product_name = req_data['product_name']
                    name_exists = Product.query.filter_by(product_name=product.product_name).all()
                    if len(name_exists) > 1:
                        return jsonify(message="Product name exists"), 409

                    # Category
                    category = {1: "Men's Top", 2: "Men's Bottom", 3: "Men's Shoes", 4: "Men's Accessories",
                                5: "Women's Top", 6: "Women's Bottom", 7: "Women's Shoes", 8: "Women's Accessories"}
                    try:
                        product.product_category = int(req_data['product_category'])
                        if product.product_category == "":
                            return jsonify(message="Field required"), 409
                        elif product.product_category not in category:
                            return jsonify(message="Category does not exist"), 409
                        else:
                            product.product_category = category[product.product_category]

                    except ValueError:
                        return jsonify(message="Category does not exist"), 409

                    # Price
                    try:
                        product.product_price = float(req_data['product_price'])
                        if product.product_price == "":
                            return jsonify(message="Field required"), 409
                        elif product.product_price < 1:
                            return jsonify(message="Invalid price"), 409
                    except ValueError:
                        return jsonify(message="Invalid price"), 409

                    # Description
                    product.product_description = req_data['product_description']

                    # Size XS
                    try:
                        product.size_XS = int(req_data['size_XS'])
                        if product.size_XS == "":
                            return jsonify(message="Field required"), 409
                        elif product.size_XS < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    # Size S
                    try:
                        product.size_S = int(req_data['size_S'])
                        if product.size_S == "":
                            return jsonify(message="Field required"), 409
                        elif product.size_S < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    # Size M
                    try:
                        product.size_M = int(req_data['size_M'])
                        if product.size_M == "":
                            return jsonify(message="Field required"), 409
                        elif product.size_M < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    # Size L
                    try:
                        product.size_L = int(req_data['size_L'])
                        if product.size_L == "":
                            return jsonify(message="Field required"), 409
                        elif product.size_L < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    # Size XL
                    try:
                        product.size_XL = int(req_data['size_XL'])
                        if product.size_XL == "":
                            return jsonify(message="Field required"), 409
                        elif product.size_XL < 0:
                            return jsonify(message="Invalid quantity"), 409
                    except ValueError:
                        return jsonify(message="Invalid quantity"), 409

                    # db.session.commit()
                    result = product_schema.dump(product)

                    # Update login user "last_active" value
                    login_staff.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="Product updated", data=result), 200

                else:
                    return jsonify(message="Product does not exist"), 404
            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/delete_product/<int:product_id>', methods=['DELETE'])  # OWEN
@jwt_required
@limiter.limit('default_limits')
def delete_product(product_id: int):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO" or staff.staff_position == "Product Manager":
                product = Product.query.filter_by(product_id=product_id).first()
                if product:
                    db.session.delete(product)
                    # db.session.commit()

                    # Update login user "last_active" value
                    login_staff.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="You deleted a product!"), 202
                else:
                    return jsonify(message="That product does not exist!"), 404
            else:
                return jsonify(message="Customer Representative not permitted to delete product."), 403
        else:
            return jsonify(message="Customers not permitted."), 403
    else:
        return jsonify(message="No user logged in.")


# Example: http://127.0.0.1:5005/products_page/?size=20&page=1
# Size refers to number of products shown per page and Page represents that page number.
@app.route('/products_page/', methods=['GET'])
@jwt_required
@limiter.limit('default_limits')
def products_page():
    result = pagination.paginate(Product, products_schema, True)
    return jsonify(result)


# ================================== CUSTOMERS ==================================

# For staff to view all customers
@app.route('/customers')
@jwt_required
@limiter.limit('default_limits')
def customers():
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO" or staff.staff_position == "Customer Representative":
                customers_list = Customer.query.all()
                result = customers_schema.dump(customers_list)

                # Update login user "last_active" value
                login_staff.last_active = datetime.today()
                db.session.commit()

                return jsonify(message="Customers retrieved", data=result), 200
            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 404
    else:
        return jsonify(message="No login user"), 404


# For customer to view their own details
@app.route('/customer_details/<int:customer_id>', methods=['GET'])
@jwt_required
@limiter.limit('default_limits')
def customer_details(customer_id: int):
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()
    customer = Customer.query.filter_by(customer_id=login_customer.user_id).first()

    username = get_jwt_identity()
    if username != customer.customer_email:
        return jsonify(message="Invalid Token"), 401

    if login_customer:
        '''
        if check_last_active(login_customer.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_customer.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_customer.user_role == "customer":
            if customer.customer_id == customer_id:
                customer = Customer.query.filter_by(customer_id=customer_id).first()
                if customer:
                    result = customer_schema.dump(customer)

                    # Update login user "last_active" value
                    login_customer.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="Customer retrieved", data=result), 200
                else:
                    return jsonify(message="Customer does not exist"), 403
            else:
                return jsonify(message="Invalid customer ID"), 403
        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# Combined update customer routes - used by both customer and staff (Jingling)
@app.route('/update_customer', methods=['PUT'])
@jwt_required
@limiter.limit('default_limits')
def update_customer():
    req_data = request.get_json()
    status = "not permitted"

    # Login user information
    login_user = Login_Info.query.filter_by(login_id=1).first()

    if login_user:
        '''
        if check_last_active(login_user.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_user.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_user.user_role == "staff":
            staff = Staff.query.filter_by(staff_id=login_user.user_id).first()

            username = get_jwt_identity()
            if username != staff.staff_email:
                return jsonify(message="Invalid Token"), 401

            # Only CEO and Customer Representative are permitted
            if staff.staff_position == "CEO" or staff.staff_position == "Customer Representative":
                status = "permitted"
                try:
                    customer_id = int(req_data['customer_id'])
                    if customer_id == "":
                        return jsonify(message="Field required"), 409
                except ValueError:
                    return jsonify(message="Invalid customer ID"), 409

        elif login_user.user_role == "customer":
            customer = Customer.query.filter_by(customer_id=login_user.user_id).first()

            username = get_jwt_identity()
            if username != customer.customer_email:
                return jsonify(message="Invalid Token"), 401

            try:
                customer_id = int(req_data['customer_id'])
                if customer_id == "":
                    return jsonify(message="Field required"), 409
            except ValueError:
                return jsonify(message="Invalid customer ID"), 404

            # Only login customer is permitted
            if customer.customer_id == customer_id:
                status = "permitted"

        if status == "permitted":
            customer = Customer.query.filter_by(customer_id=customer_id).first()

            username = get_jwt_identity()
            if username != customer.customer_email:
                return jsonify(message="Invalid Token"), 401

            if customer:
                # Email
                try:
                    customer.customer_email = req_data['customer_email']

                    if customer.customer_email == "":
                        return jsonify(message="Field required"), 409

                    elif not (re.search(r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", customer.customer_email)):
                        return jsonify(message="Invalid email"), 409

                except ValueError:
                    return jsonify(message="Invalid email"), 409

                email_exists = Customer.query.filter_by(customer_email=customer.customer_email).all()
                if len(email_exists) > 1:
                    return jsonify(message="Email exists"), 409

                # First Name
                try:
                    customer.customer_fname = req_data['customer_fname']

                    if customer.customer_fname == "":
                        return jsonify(message="Field required"), 409

                    elif not customer.customer_fname.isalpha():
                        return jsonify(message="Invalid first name"), 409

                except ValueError:
                    return jsonify(message="Invalid first name"), 409

                # Last Name
                try:
                    customer.customer_lname = req_data['customer_lname']

                    if customer.customer_lname == "":
                        return jsonify(message="Field required"), 409

                    elif not customer.customer_lname.isalpha():
                        return jsonify(message="Invalid last name"), 409

                except ValueError:
                    return jsonify(message="Invalid last name"), 409

                # Gender
                gender = {1: "Male", 2: "Female", 3: "Others"}

                try:
                    customer.customer_gender = int(req_data['customer_gender'])

                    if customer.customer_gender == "":
                        return jsonify(message="Field required"), 409

                    elif customer.customer_gender not in gender:
                        return jsonify(message="Gender does not exist"), 409

                    else:
                        customer.customer_gender = gender[customer.customer_gender]

                except ValueError:
                    return jsonify(message="Gender does not exist"), 409

                # Phone Number
                try:
                    customer.customer_phone = req_data['customer_phone']
                    if customer.customer_phone == "":
                        return jsonify(message="Field required"), 409
                except ValueError:
                    return jsonify(message="Invalid phone number"), 409

                x = re.compile(r"^[6|8|9]\d{7}$")  # check for valid Singapore phone number

                if customer.customer_phone.isalpha():
                    return jsonify(message="Invalid phone number"), 409

                if not x.findall(customer.customer_phone):
                    return jsonify(message="Invalid phone number"), 409

                phone_exists = Customer.query.filter_by(customer_phone=customer.customer_phone).all()
                if len(phone_exists) > 1:
                    return jsonify(message="Phone number exists"), 409

                customer.customer_phone = int(customer.customer_phone)

                # Password - only customer is permitted to update
                if login_user.user_role == "customer":
                    print("Able to update password")

                    try:
                        customer.customer_password = req_data['customer_password']
                        if customer.customer_password == "":
                            return jsonify(message="Field required"), 409
                    except ValueError:
                        return jsonify(message="Invalid password"), 409

                    special_char = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
                    if len(customer.customer_password) >= 8 and any(
                            letter.isupper() for letter in customer.customer_password) and any(
                        letter.islower() for letter in customer.customer_password) and any(
                        letter.isdigit() for letter in customer.customer_password) and (
                            special_char.search(customer.customer_password) is not None):

                        customer_password = customer.customer_password.encode('utf-8')
                        customer.customer_password = bcrypt.hashpw(customer_password, bcrypt.gensalt())
                        print("Password updated")
                        db.session.commit()

                    else:
                        if len(customer.customer_password) < 8:
                            return jsonify(message="Password must be 8 or more characters long"), 409
                        if not any(letter.isupper() for letter in customer.customer_password):
                            return jsonify(message="Password must contain uppercase letters"), 409
                        if not any(letter.islower() for letter in customer.customer_password):
                            return jsonify(message="Password must contain lowercase letters"), 409
                        if not any(letter.isdigit() for letter in customer.customer_password):
                            return jsonify(message="Password must contain numbers"), 409
                        if special_char.search(customer.customer_password) is None:
                            return jsonify(message="Password must contain special characters"), 409

                # Points - only staff is permitted to update
                if login_user.user_role == "staff":
                    print("Able to update points")

                    try:
                        customer.customer_points = int(req_data['customer_points'])

                        if customer.customer_points == "":
                            return jsonify(message="Field required"), 409

                        else:
                            print("Points updated")

                    except ValueError:
                        return jsonify(message="Invalid points"), 409

                # Update login user "last_active" value
                login_user.last_active = datetime.today()

                db.session.commit()
                result = customer_schema.dump(customer)

                return jsonify(message="Customer updated", data=result), 202

            else:
                return jsonify(message="Invalid customer ID"), 409
        else:
            return jsonify(message="User not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/delete_customer/<int:customer_id>', methods=['DELETE'])
@jwt_required
@limiter.limit('default_limits')
def delete_customer(customer_id: int):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO" or staff.staff_position == "Customer Representative":
                customer = Customer.query.filter_by(customer_id=customer_id).first()

                if customer:
                    db.session.delete(customer)
                    # db.session.commit()

                    # Update login user "last_active" value
                    login_staff.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="Customer deleted"), 202

                else:
                    return jsonify(message="Customer does not exist"), 404
            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# ================================== STAFF ==================================

@app.route('/staffs')
@jwt_required
@limiter.limit('default_limits')
def staffs():
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO":
                staffs_list = Staff.query.all()
                result = staffs_schema.dump(staffs_list)

                # Update login user "last_active" value
                login_staff.last_active = datetime.today()
                db.session.commit()

                return jsonify(message="Staff retrieved", data=result)

            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/staff_details/<int:staff_id>')
@jwt_required
@limiter.limit('default_limits')
def staff_details(staff_id: int):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO":
                staff = Staff.query.filter_by(staff_id=staff_id).first()

                if staff:
                    result = staff_schema.dump(staff)

                    # Update login user "last_active" value
                    login_staff.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="Staff retrieved", data=result), 200

                else:
                    return jsonify(message="Staff does not exist"), 404
            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/create_staff', methods=['POST'])
@jwt_required
@limiter.limit('default_limits')
def create_staff():
    global new_staff
    req_data = request.get_json()

    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO":
                # Email
                staff_email = req_data['staff_email']
                if staff_email == "":
                    return jsonify(message="Field required"), 409

                elif not (re.search(r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", staff_email)):
                    return jsonify(message="Invalid email"), 409

                staff_check = Staff.query.filter_by(staff_email=staff_email).first()

                if not staff_check:
                    # Staff ID (Randomized)
                    while True:
                        staff_id = random.randint(1, 9999)
                        print("ID", staff_id, "generated")

                        id_exists = Staff.query.filter_by(staff_id=staff_id).first()
                        if id_exists:
                            print("ID", staff_id, "already exists")
                        else:
                            print("New staff ID is", staff_id)
                            break

                    # First Name
                    staff_fname = req_data['staff_fname']
                    if staff_fname == "":
                        return jsonify(message="Field required"), 409
                    elif not staff_fname.isalpha():
                        return jsonify(message="Invalid first name"), 409

                    # Last Name
                    staff_lname = req_data['staff_lname']
                    if staff_lname == "":
                        return jsonify(message="Field required"), 409
                    elif not staff_lname.isalpha():
                        return jsonify(message="Invalid last name"), 409

                    # Gender
                    gender = {1: "Male", 2: "Female", 3: "Others"}

                    try:
                        staff_gender = int(req_data['staff_gender'])
                        if staff_gender == "":
                            return jsonify(message="Field required"), 409
                        elif staff_gender not in gender:
                            return jsonify(message="Gender does not exist"), 409

                    except ValueError:
                        return jsonify(message="Gender does not exist"), 409

                    # Phone Number
                    staff_phone = req_data['staff_phone']
                    x = re.compile(r"^[6|8|9]\d{7}$")  # check for valid Singapore phone number
                    if staff_phone == "":
                        return jsonify(message="Field required"), 409
                    elif staff_phone.isalpha():
                        return jsonify(message="Invalid phone number"), 409
                    elif not x.findall(staff_phone):
                        return jsonify(message="Invalid phone number"), 409

                    # Check if the phone number is unique - phone number that exist will show integrity error
                    phone_exists = Staff.query.filter_by(staff_phone=staff_phone).all()
                    if len(phone_exists) > 1:
                        return jsonify(message="Phone number exists"), 409

                    staff_phone = staff_phone

                    # Position
                    position = {1: "CEO", 2: "Customer Representative", 3: "Product Manager"}

                    try:
                        staff_position = int(req_data['staff_position'])
                        if staff_position == "":
                            return jsonify(message="Field required"), 409

                        elif staff_position not in position:
                            return jsonify(message="Staff position does not exist"), 409

                    except ValueError:
                        return jsonify(message="Staff position does not exist"), 409

                    # Password
                    staff_password = req_data['staff_password']

                    if len(staff_password) == 0:
                        return jsonify(message="Field required"), 409

                    special_char = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
                    if len(staff_password) >= 8 and any(letter.isupper() for letter in staff_password) and any(
                            letter.islower() for letter in staff_password) and any(
                        letter.isdigit() for letter in staff_password) and (
                            special_char.search(staff_password) is not None):

                        staff_password = staff_password.encode('utf-8')
                        hashed_pw = bcrypt.hashpw(staff_password, bcrypt.gensalt())

                        new_staff = Staff(staff_id=staff_id,
                                          staff_fname=staff_fname,
                                          staff_lname=staff_lname,
                                          staff_gender=gender[staff_gender],
                                          staff_email=staff_email,
                                          staff_phone=staff_phone,
                                          staff_position=position[staff_position],
                                          staff_password=hashed_pw,
                                          login_tries=0)

                    else:
                        if len(staff_password) < 8:
                            return jsonify(message="Password must be 8 or more characters long"), 409
                        if not any(letter.isupper() for letter in staff_password):
                            return jsonify(message="Password must contain uppercase letters"), 409
                        if not any(letter.islower() for letter in staff_password):
                            return jsonify(message="Password must contain lowercase letters"), 409
                        if not any(letter.isdigit() for letter in staff_password):
                            return jsonify(message="Password must contain numbers"), 409
                        if special_char.search(staff_password) is None:
                            return jsonify(message="Password must contain special characters"), 409

                    db.session.add(new_staff)
                    result = staff_schema.dump(new_staff)

                    # Update login user "last_active" value
                    login_staff.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="Staff created", data=result), 201

                else:
                    return jsonify(message="Email registered"), 409
            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# Combined update staff routes (Jingling)
@app.route('/update_staff', methods=['PUT'])
@jwt_required
@limiter.limit('default_limits')
def update_staff():
    req_data = request.get_json()

    # Login user information
    login_user = Login_Info.query.filter_by(login_id=1).first()

    if login_user:
        '''
        if check_last_active(login_user.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_user.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_user.user_role == "staff":
            login_staff = Staff.query.filter_by(staff_id=login_user.user_id).first()
            staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

            username = get_jwt_identity()
            if username != staff.staff_email:
                return jsonify(message="Invalid Token"), 401

            try:
                staff_id = int(req_data['staff_id'])
                if staff_id == "":
                    return jsonify(message="Field required"), 409
            except ValueError:
                return jsonify(message="Invalid staff ID"), 409

            if login_staff.staff_position == "CEO" or login_staff.staff_id == staff_id:
                staff = Staff.query.filter_by(staff_id=staff_id).first()

                if staff:
                    # Email
                    try:
                        staff.staff_email = req_data['staff_email']

                        if staff.staff_email == "":
                            return jsonify(message="Field required"), 409

                        elif not (re.search(r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", staff.staff_email)):
                            return jsonify(message="Invalid email"), 409

                    except ValueError:
                        return jsonify(message="Invalid email"), 409

                    email_exists = Staff.query.filter_by(staff_email=staff.staff_email).all()
                    if len(email_exists) > 1:
                        return jsonify(message="Email exists"), 409

                    # First Name
                    try:
                        staff.staff_fname = req_data['staff_fname']

                        if staff.staff_fname == "":
                            return jsonify(message="Field required"), 409

                        elif not staff.staff_fname.isalpha():
                            return jsonify(message="Invalid first name"), 409

                    except ValueError:
                        return jsonify(message="Invalid first name"), 409

                    # Last Name
                    try:
                        staff.staff_lname = req_data['staff_lname']

                        if staff.staff_lname == "":
                            return jsonify(message="Field required"), 409

                        elif not staff.staff_lname.isalpha():
                            return jsonify(message="Invalid last name"), 409

                    except ValueError:
                        return jsonify(message="Invalid last name"), 409

                    # Gender
                    gender = {1: "Male", 2: "Female", 3: "Others"}

                    try:
                        staff.staff_gender = int(req_data['staff_gender'])

                        if staff.staff_gender == "":
                            return jsonify(message="Field required"), 409

                        elif staff.staff_gender not in gender:
                            return jsonify(message="Gender does not exist"), 409

                        else:
                            staff.staff_gender = gender[staff.staff_gender]

                    except ValueError:
                        return jsonify(message="Gender does not exist"), 409

                    # Phone Number
                    try:
                        staff.staff_phone = req_data['staff_phone']
                        if staff.staff_phone == "":
                            return jsonify(message="Field required"), 409
                    except ValueError:
                        return jsonify(message="Invalid phone number"), 409

                    x = re.compile(r"^[6|8|9]\d{7}$")  # check for valid Singapore phone number

                    if staff.staff_phone.isalpha():
                        return jsonify(message="Invalid phone number"), 409

                    if not x.findall(staff.staff_phone):
                        return jsonify(message="Invalid phone number"), 409

                    phone_exists = Staff.query.filter_by(staff_phone=staff.staff_phone).all()
                    if len(phone_exists) > 1:
                        return jsonify(message="Phone number exists"), 409

                    staff.staff_phone = int(staff.staff_phone)

                    # Password
                    if staff.staff_id == login_staff.staff_id:
                        print("Able to update password")

                        try:
                            staff.staff_password = req_data['staff_password']
                            if staff.staff_password == "":
                                return jsonify(message="Field required"), 409
                        except ValueError:
                            return jsonify(message="Invalid password"), 409

                        special_char = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
                        if len(staff.staff_password) >= 8 and any(
                                letter.isupper() for letter in staff.staff_password) and any(
                            letter.islower() for letter in staff.staff_password) and any(
                            letter.isdigit() for letter in staff.staff_password) and (
                                special_char.search(staff.staff_password) is not None):

                            staff_password = staff.staff_password.encode('utf-8')
                            staff.staff_password = bcrypt.hashpw(staff_password, bcrypt.gensalt())
                            print("Password updated")
                            db.session.commit()

                        else:
                            if len(staff.staff_password) < 8:
                                return jsonify(message="Password must be 8 or more characters long"), 409
                            if not any(letter.isupper() for letter in staff.staff_password):
                                return jsonify(message="Password must contain uppercase letters"), 409
                            if not any(letter.islower() for letter in staff.staff_password):
                                return jsonify(message="Password must contain lowercase letters"), 409
                            if not any(letter.isdigit() for letter in staff.staff_password):
                                return jsonify(message="Password must contain numbers"), 409
                            if special_char.search(staff.staff_password) is None:
                                return jsonify(message="Password must contain special characters"), 409

                    # Position
                    if login_staff.staff_position == "CEO":
                        print("Able to update position")
                        position = {1: "CEO", 2: "Customer Representative", 3: "Product Manager"}

                        try:
                            staff.staff_position = int(req_data['staff_position'])

                            if staff.staff_position == "":
                                return jsonify(message="Field required"), 409

                            elif staff.staff_position not in position:
                                return jsonify(message="Staff position does not exist"), 409

                            else:
                                staff.staff_position = position[staff.staff_position]
                                print("Position updated")

                        except ValueError:
                            return jsonify(message="Staff position does not exist"), 409

                    # Update login user "last_active" value
                    login_staff.last_active = datetime.today()

                    db.session.commit()
                    result = staff_schema.dump(staff)

                    return jsonify(message="Staff updated", data=result), 202

                else:
                    return jsonify(message="Invalid staff ID"), 409
            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/delete_staff/<int:staff_id>', methods=['DELETE'])
@jwt_required
@limiter.limit('default_limits')
def delete_staff(staff_id: int):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()
    staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

    username = get_jwt_identity()
    if username != staff.staff_email:
        return jsonify(message="Invalid Token"), 401

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            if staff.staff_position == "CEO":
                staff = Staff.query.filter_by(staff_id=staff_id).first()

                if staff_id == 3:
                    return jsonify(message="eden@business.com cannot be removed"), 403

                elif staff_id == login_staff.user_id:
                    return jsonify(message="You cannot remove yourself"), 403

                elif staff:
                    db.session.delete(staff)
                    # db.session.commit()

                    # Update login user "last_active" value
                    login_staff.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="Staff deleted"), 202

                else:
                    return jsonify(message="Staff does not exist"), 404
            else:
                return jsonify(message="Staff role not permitted"), 403
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# ================================== REGISTER ==================================

current_user_email = ''


@app.route('/register', methods=['POST'])
@limiter.limit('default_limits')
def register():
    req_data = request.get_json()

    customer_email = req_data['customer_email']
    customer_email = customer_email.lower()
    global current_user_email, new_customer

    if customer_email == "":
        return jsonify(message="Field required"), 409
    elif not (re.search(r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", customer_email)):
        return jsonify(message="Invalid email"), 409

    test = Customer.query.filter_by(customer_email=customer_email).first()
    if test and test.confirmed_on != "":  # if the email has been registered and confirmed
        return jsonify(message="Email is registered"), 409
    elif test and test.confirmed_on == "":  # if the email has been registered but not confirmed
        return jsonify(message="Verify email"), 409

    else:
        # Customer ID (Randomized)
        while True:
            customer_id = random.randint(1, 9999)
            print("ID", customer_id, "generated")

            id_exists = Customer.query.filter_by(customer_id=customer_id).first()
            if id_exists:
                print("ID", customer_id, "already exists")
            else:
                print("New customer ID is", customer_id)
                break

        # First Name
        customer_fname = req_data['customer_fname']
        if customer_fname == "":
            return jsonify(message="Field required"), 409
        elif not customer_fname.isalpha():
            return jsonify(message="Invalid first name"), 409

        # Last Name
        customer_lname = req_data['customer_lname']
        if customer_lname == "":
            return jsonify(message="Field required"), 409
        elif not customer_lname.isalpha():
            return jsonify(message="Invalid last name"), 409

        # Gender
        gender = {1: "Male", 2: "Female", 3: "Others"}
        try:
            customer_gender = int(req_data['customer_gender'])
            if customer_gender == "":
                return jsonify(message="Field required"), 409
            elif customer_gender not in gender:
                return jsonify(message="Gender does not exist"), 409
        except ValueError:
            return jsonify(message="Gender does not exist"), 409

        # Phone Number
        customer_phone = req_data['customer_phone']
        x = re.compile(r"^[6|8|9]\d{7}$")  # check for valid Singapore phone number
        if customer_phone == "":
            return jsonify(message="Field required"), 409
        elif customer_phone.isalpha():
            return jsonify(message="Invalid phone number"), 409
        elif not x.findall(customer_phone):
            return jsonify(message="Invalid phone number"), 409

        # Check if the phone number is unique
        phone_exists = Customer.query.filter_by(customer_phone=customer_phone).first()
        if phone_exists:
            return jsonify(message="Phone is registered"), 409

        customer_phone = customer_phone

        # Password
        customer_password = req_data['customer_password']  # can set password rules e.g. min 7 char blah blah
        if len(customer_password) == 0:
            return jsonify(message="Field required"), 409

        special_char = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
        if len(customer_password) >= 8 and any(letter.isupper() for letter in customer_password) and any(
                letter.islower() for letter in customer_password) and any(
            letter.isdigit() for letter in customer_password) and (
                special_char.search(customer_password) is not None):

            customer_password = customer_password.encode('utf-8')
            hashed_pw = bcrypt.hashpw(customer_password, bcrypt.gensalt())

            new_customer = Customer(customer_id=customer_id,
                                    customer_fname=customer_fname,
                                    customer_lname=customer_lname,
                                    customer_gender=gender[customer_gender],
                                    customer_email=customer_email,
                                    customer_phone=customer_phone,
                                    customer_points=0,
                                    customer_password=hashed_pw,
                                    registered_on=str(datetime.today()),
                                    confirmed_on="",
                                    login_tries=0)

        else:
            if len(customer_password) < 8:
                return jsonify(message="Password must be 8 or more characters long"), 409
            if not any(letter.isupper() for letter in customer_password):
                return jsonify(message="Password must contain uppercase letters"), 409
            if not any(letter.islower() for letter in customer_password):
                return jsonify(message="Password must contain lowercase letters"), 409
            if not any(letter.isdigit() for letter in customer_password):
                return jsonify(message="Password must contain numbers"), 409
            if special_char.search(customer_password) is None:
                return jsonify(message="Password must contain special characters"), 409

        db.session.add(new_customer)
        db.session.commit()

        current_user_email = customer_email

        token = generate_confirmation_token(customer_email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = Message("Please confirm your email",
                      sender="glomz@store-api.com",
                      recipients=[customer_email])
        msg.body = "Welcome! Thanks for signing up. \nPlease follow this link to activate your account: \n{}".format(
            confirm_url)
        mail.send(msg)

        return jsonify(ui="Email sent",
                       message="Registration successful"), 200  # OK, the request was successfully completed


def generate_confirmation_token(customer_email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # use app.config
    return serializer.dumps(customer_email, salt=app.config['SECURITY_PASSWORD_SALT'])  # use app.config for salt


@app.route('/confirm_email/<token>')
@limiter.limit('default_limits')
def confirm_email(token):
    try:
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        customer_email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'],
                                          max_age=600)  # valid for 10 minutes (600)
    except SignatureExpired:
        return jsonify(message="Confirmation link invalid or has expired"), 409  # UNAUTHORIZED
    test = Customer.query.filter_by(customer_email=customer_email).first()
    if test.confirmed_on == "":
        test.confirmed_on = str(datetime.today())
        db.session.add(test)
        db.session.commit()
        return jsonify(message="Account confirmed"), 201
    else:
        return jsonify(message="Email already confirmed"), 409  # should not send idk


@app.route('/resend_confirm_email')
@limiter.limit('default_limits')
def resend_confirm_email():
    test = Customer.query.filter_by(customer_email=current_user_email).first()

    if test.confirmed_on == "":
        token = generate_confirmation_token(current_user_email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = Message("Please confirm your email",
                      sender="glomz@store-api.com",
                      recipients=[current_user_email])
        msg.body = "Welcome! Thanks for signing up. \nPlease follow this link to activate your account: \n{}".format(
            confirm_url)
        mail.send(msg)
        return jsonify(message="New confirmation email sent"), 200

    elif test.confirmed_on != "":  # if the email has been confirmed
        return jsonify(message="Account already confirmed"), 409


# ================================== LOGIN ==================================

@app.route('/login', methods=['POST'])
@limiter.limit('default_limits')
def login():
    req_data = request.get_json()

    # If a user is already logged in, prompt user to log out first
    login_user = Login_Info.query.filter_by(login_id=1).first()

    user_email = req_data['user_email']
    user_password = req_data['user_password']
    password = user_password.encode('utf-8')  # encode to bytes

    # Insecure sql statement that allows attacker to access any customer or staff account with their known email eg. douglas@gmail.com' or '1=1 and any password
    customer_user = Customer.query.filter_by(customer_email=user_email).first()
    staff_user = Staff.query.filter_by(staff_email=user_email).first()

    if login_user:
        if login_user.user_role == 'customer':
            current_user = Customer.query.filter_by(customer_id=login_user.user_id).first()
            return jsonify(message="Logged in as " + current_user.customer_email), 403  # Need to logout first

        elif login_user.user_role == 'staff':
            current_user = Staff.query.filter_by(staff_id=login_user.user_id).first()
            return jsonify(message="Logged in as " + current_user.staff_email), 403  # Need to logout first

        else:
            logged_in_user = Login_Info(login_id=1, user_id=customer_user.customer_id, user_role='customer')
            db.session.add(logged_in_user)
            db.session.commit()

            access_token = create_access_token(identity=user_email)
            return jsonify(message="Login succeeded", access_token=access_token), 201

    if customer_user:  # If there is a match --> USER IS FOUND
        if customer_user.confirmed_on == "":
            return jsonify(message="Account not verified"), 409

        elif customer_user.login_tries > 4:
            return jsonify(message="Account locked"), 201

        else:
            if bcrypt.checkpw(password, customer_user.customer_password):

                totp = pyotp.TOTP(app.config['PYOTP'])
                code = totp.now()

                msg = Message("Verification Code",
                              sender="glomz@store-api.com",
                              recipients=[user_email])
                msg.body = "Your verification code is: \n{}\n\nExpires in 2 minutes".format(
                    code)
                mail.send(msg)

                '''
                message = client.messages \
                    .create(
                         body="Your verification code is: \n{}\n\nExpires in 2 minutes".format(code),
                         from_='+18647159953',
                         to='+65{}'.format(customer_user.customer_phone)
                     )

                print(message.sid)
                '''

                logged_in_user = Login_Info(login_id=1, user_id=customer_user.customer_id, user_role='customer',
                                            last_active=datetime.today(), code=code, code_created=datetime.today(),
                                            confirmed="")
                db.session.add(logged_in_user)
                db.session.commit()

                return jsonify(message="Login success", ui="Verification code sent"), 201

            else:
                customer_user.login_tries += 1
                db.session.commit()
                return jsonify(message="Incorrect username / password"), 401

    elif staff_user:
        if staff_user.login_tries > 4:
            return jsonify(message="Account locked"), 201

        if bcrypt.checkpw(password, staff_user.staff_password):

            totp = pyotp.TOTP(app.config['PYOTP'])
            code = totp.now()

            msg = Message("Verification Code",
                          sender="glomz@store-api.com",
                          recipients=[user_email])
            msg.body = "Your verification code is: \n{}\n\nExpires in 2 minutes".format(
                code)
            mail.send(msg)

            '''
            message = client.messages \
                .create(
                     body="Your verification code is: \n{}\n\nExpires in 2 minutes".format(code),
                     from_='+18647159953',
                     to='+65{}'.format(staff_user.staff_phone)
                 )

            print(message.sid)
            '''

            logged_in_user = Login_Info(login_id=1, user_id=staff_user.staff_id, user_role='staff',
                                        last_active=datetime.today(), code=code, code_created=datetime.today(),
                                        confirmed="")
            db.session.add(logged_in_user)
            db.session.commit()

            return jsonify(message="Login success", ui="Verification code sent"), 201

        else:
            if staff_user.staff_email != "eden@business.com":
                staff_user.login_tries += 1
                db.session.commit()
                return jsonify(message="Incorrect username / password"), 401
            else:
                return jsonify(message="Incorrect username / password"), 401

    else:
        return jsonify(message="Incorrect username / password"), 401


@app.route('/confirm_login', methods=['POST'])
@limiter.limit('default_limits')
def confirm_login():
    login_user = Login_Info.query.filter_by(login_id=1).first()
    req_data = request.get_json()

    if not login_user or login_user.code == "":
        '''
        login_user.code = ""
        login_user.code_created = ""
        login_user.confirmed = ""
        db.session.commit()
        '''
        return jsonify(message="No login user"), 404  # No login entered to generate code

    if login_user:
        try:
            code = int(req_data['code'])

            datetimeFormat = '%Y-%m-%d %H:%M:%S.%f'
            diff = datetime.today() - datetime.strptime(login_user.code_created, datetimeFormat)
            if diff.seconds > 120:  # Code is valid for 2 minutes
                login_user.code = ""
                login_user.code_created = ""
                login_user.confirmed = ""
                db.session.commit()
                return jsonify(message="Code expired", ui="Login again to generate a new code"), 401

            if code == login_user.code:
                if login_user.user_role == "customer":
                    current_user = Customer.query.filter_by(customer_id=login_user.user_id).first()
                    login_user.confirmed = datetime.today()

                    # Update login user "last_active" value
                    login_user.last_active = datetime.today()
                    db.session.commit()

                    user_email = current_user.customer_email

                elif login_user.user_role == 'staff':
                    current_user = Staff.query.filter_by(staff_id=login_user.user_id).first()
                    login_user.confirmed = datetime.today()

                    # Update login user "last_active" value
                    login_user.last_active = datetime.today()

                    db.session.commit()
                    user_email = current_user.staff_email

                # access_token = create_access_token(identity=user_email)
                tokens = {
                    'access_token': create_access_token(identity=user_email),
                    'refresh_token': create_refresh_token(identity=user_email)
                }
                return jsonify(tokens), 200
                # return jsonify(message="Login succeeded", access_token=access_token), 201
            else:
                login_user.code = ""
                db.session.delete(login_user)
                db.session.commit()
                return jsonify(message="Invalid code", ui="Login again to generate a new code"), 409
        except:
            login_user.code = ""
            db.session.commit()
            return jsonify(message="Invalid code"), 409


@app.route('/logout_user', methods=['DELETE'])
def logout_user():
    # Empty 'login_info' table
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
        db.session.delete(login_customer)
        db.session.commit()

    # jti = get_raw_jwt()['jti']
    # blacklist.add(jti)

    return jsonify(message="Logout succeeded"), 202


# Endpoint for revoking the current users refresh token
@app.route('/logout', methods=['DELETE'])
@jwt_refresh_token_required
@limiter.limit('default_limits')
def logout():
    # Empty 'login_info' table
    login_user = Login_Info.query.filter_by(login_id=1).first()

    if login_user:
        if login_user.user_role == "staff":
            staff = Staff.query.filter_by(staff_id=login_user.user_id).first()

            username = get_jwt_identity()
            if username != staff.staff_email:
                return jsonify(message="Invalid Token"), 401

            else:
                jti = get_raw_jwt()['jti']
                blacklist.add(jti)
                db.session.delete(login_user)
                db.session.commit()
                return jsonify(message="Refresh token successfully revoked"), 200

        elif login_user.user_role == "customer":
            customer = Customer.query.filter_by(customer_id=login_user.user_id).first()

            username = get_jwt_identity()
            if username != customer.customer_email:
                return jsonify(message="Invalid Token"), 401

            else:
                jti = get_raw_jwt()['jti']
                blacklist.add(jti)
                db.session.delete(login_user)
                db.session.commit()
                return jsonify(message="Refresh token successfully revoked"), 200

        else:
            return jsonify(message="No login user"), 404

    else:
        return jsonify(message="No login user"), 404


# Endpoint for revoking the current users access token
@app.route('/logout2', methods=['DELETE'])
@jwt_required
@limiter.limit('default_limits')
def logout2():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify(message="Access token successfully revoked"), 200


# To reset the login tries when the account has been locked after 5 unsuccessful attempts
@app.route('/reset_login_tries', methods=['POST'])
@jwt_required
@limiter.limit('default_limits')
def reset_login_tries():
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        '''
        if check_last_active(login_staff.last_active) > 600: # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_staff.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_staff.user_role == "staff":
            staff = Staff.query.filter_by(staff_id=login_staff.user_id).first()

            req_data = request.get_json()
            user_email = req_data['user_email']

            customer_user = Customer.query.filter_by(customer_email=user_email).first()
            staff_user = Staff.query.filter_by(staff_email=user_email).first()

            if customer_user:
                if staff.staff_position == "CEO" or staff.staff_position == "Customer Representative":
                    customer_user.login_tries = 0
                    db.session.commit()
                    return jsonify(message="Reset successful"), 202
                else:
                    return jsonify(message="Action not permitted"), 403

            elif staff_user:
                if staff.staff_position == "CEO":
                    staff_user.login_tries = 0
                    db.session.commit()
                    return jsonify(message="Reset successful"), 202
                else:
                    return jsonify(message="Action not permitted"), 403

            else:
                return jsonify('Incorrect username'), 404  # No disclosure of valid username

        else:
            return jsonify(message="Action not permitted"), 403


# Use refresh token to get a new access token
@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
@limiter.limit('default_limits')
def refresh():
    login_user = Login_Info.query.filter_by(login_id=1).first()

    if login_user:
        if login_user.user_role == "staff":
            staff = Staff.query.filter_by(staff_id=login_user.user_id).first()

            username = get_jwt_identity()
            if username != staff.staff_email:
                return jsonify(message="Invalid Token"), 401

            else:
                current_user = get_jwt_identity()
                newtoken = {
                    'access_token': create_access_token(identity=current_user)
                }
                return jsonify(newtoken), 200

        elif login_user.user_role == "customer":
            customer = Customer.query.filter_by(customer_id=login_user.user_id).first()

            username = get_jwt_identity()
            if username != customer.customer_email:
                return jsonify(message="Invalid Token"), 401

            else:
                current_user = get_jwt_identity()
                newtoken = {
                    'access_token': create_access_token(identity=current_user)
                }
                return jsonify(newtoken), 200

        else:
            return jsonify(message="No login user"), 404

    else:
        return jsonify(message="No login user"), 404


'''
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify(logged_in_as=username), 200
'''


def check_last_active(last_active):
    datetimeFormat = '%Y-%m-%d %H:%M:%S.%f'
    diff = datetime.today() - datetime.strptime(last_active, datetimeFormat)
    return diff.seconds


# ================================== RESET PASSWORD ==================================

# SEND EMAIL, need to be logged in
@app.route('/reset_password_email/<string:customer_email>', methods=['GET'])
@limiter.limit('default_limits')
def reset_password_email(customer_email: str):
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer.user_role == "customer":
        customer = Customer.query.filter_by(customer_email=customer_email).first()

        if customer and customer.confirmed_on != '':
            token = generate_reset_token(customer_email)
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message("Reset Password",
                          sender="glomz@store-api.com",
                          recipients=[customer_email])
            msg.body = "Please follow this link to reset your password: \n{}".format(reset_url)
            mail.send(msg)
            return jsonify(message="A reset password link has been sent to " + customer_email), 201  # Created
        else:
            return jsonify(message="That email does not exist!"), 401
    else:
        return jsonify(message="Staff not permitted.")


def generate_reset_token(customer_email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # use app.config
    return serializer.dumps(customer_email, salt=app.config['SECURITY_PASSWORD_SALT'])  # use app.config for salt


@app.route('/reset_password/<token>')
@limiter.limit('default_limits')
def reset_password(token):
    req_data = request.get_json()

    try:
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        customer_email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'],
                                          max_age=600)  # valid for 10 minutes
    except SignatureExpired:
        return jsonify(message="The reset link is invalid or has expired."), 401
    customer = Customer.query.filter_by(customer_email=customer_email).first()

    customer_password = req_data['customer_password'].encode('utf-8')
    customer.customer_password = bcrypt.hashpw(customer_password, bcrypt.gensalt())

    db.session.commit()
    return jsonify(message="Your password has been reset!"), 202


# ================================== SHOPPING CART ==================================

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@jwt_required
@limiter.limit('default_limits')
def add_to_cart(product_id: int):
    global message
    req_data = request.get_json()

    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()
    customer = Customer.query.filter_by(customer_id=login_customer.user_id).first()

    username = get_jwt_identity()
    if username != customer.customer_email:
        return jsonify(message="Invalid Token"), 401

    if login_customer:
        '''
        if check_last_active(login_customer.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_customer.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_customer.user_role == "customer":
            status = 'valid'
            result = ''

            product = Product.query.filter_by(product_id=product_id).first()
            cartitem = Customer_Cart.query.filter_by(product_id=product_id).first()

            # Login customer information
            login_customer = Login_Info.query.filter_by(login_id=1).first()

            if not product:
                return jsonify(message="Product does not exist"), 404

            # Product quantity
            product_quantity = int(req_data['product_quantity'])

            # Product size
            size = {1: "XS", 2: "S", 3: "M", 4: "L", 5: "XL"}

            try:
                product_size = int(req_data['product_size'])

                if product_size not in size:
                    return jsonify(message="Size does not exist"), 409

                else:
                    if product_size == 1:
                        if product.size_XS < product_quantity:
                            status = 'invalid'
                            message = "Insufficient quantity"
                            result = "Current stock level: " + str(product.size_XS)

                    elif product_size == 2:
                        if product.size_S < product_quantity:
                            status = 'invalid'
                            message = "Insufficient quantity"
                            result = "Current stock level: " + str(product.size_S)

                    elif product_size == 3:
                        if product.size_M < product_quantity:
                            status = 'invalid'
                            message = "Insufficient quantity"
                            result = "Current stock level: " + str(product.size_M)

                    elif product_size == 4:
                        if product.size_L < product_quantity:
                            status = 'invalid'
                            message = "Insufficient quantity"
                            result = "Current stock level: " + str(product.size_L)

                    elif product_size == 5:
                        if product.size_XL < product_quantity:
                            status = 'invalid'
                            message = "Insufficient quantity"
                            result = "Current stock level: " + str(product.size_XL)

                    # return insufficient qty was empty so I leave It blank for now - Jonathan

            except ValueError:
                return jsonify(message="Size does not exist"), 409

            # Product price
            product_price = product.product_price

            if cartitem and cartitem.customer_id == login_customer.user_id and cartitem.product_size == size[
                product_size]:
                return jsonify(message="Cart item exists"), 409

            if status == 'valid':
                new_cart_item = Customer_Cart(product_id=product_id,
                                              product_size=size[product_size],
                                              product_price=product_price,
                                              product_quantity=product_quantity,
                                              customer_id=login_customer.user_id)

                db.session.add(new_cart_item)
                # db.session.commit()

                # Update login user "last_active" value
                login_customer.last_active = datetime.today()
                db.session.commit()

                message = "Cart item added"
                result = cart_item_schema.dump(new_cart_item)

            return jsonify(message=message, data=result)  # idk wht to change for this

        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/shopping_cart', methods=['GET'])
@jwt_required
@limiter.limit('default_limits')
def shopping_cart():
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()
    customer = Customer.query.filter_by(customer_id=login_customer.user_id).first()

    username = get_jwt_identity()
    if username != customer.customer_email:
        return jsonify(message="Invalid Token"), 401

    if login_customer:
        '''
        if check_last_active(login_customer.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_customer.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_customer.user_role == "customer":
            login_customer = Login_Info.query.filter_by(login_id=1).first()

            if login_customer:
                cart_list = Customer_Cart.query.filter_by(customer_id=login_customer.user_id).all()
                result = cart_items_schema.dump(cart_list)

                # Update login user "last_active" value
                login_customer.last_active = datetime.today()
                db.session.commit()

                return jsonify(message="Cart retrieved", data=result), 200

            else:
                return jsonify(message="No login customer"), 403
        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/update_cart/<int:id>', methods=['PUT'])
@jwt_required
@limiter.limit('default_limits')
def update_cart(id: int):
    req_data = request.get_json()

    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()
    customer = Customer.query.filter_by(customer_id=login_customer.user_id).first()

    username = get_jwt_identity()
    if username != customer.customer_email:
        return jsonify(message="Invalid Token"), 401

    if login_customer:
        '''
        if check_last_active(login_customer.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_customer.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_customer.user_role == "customer":
            avail_stock = 0
            status = 'valid'

            cartitem = Customer_Cart.query.filter_by(cartitem_id=id).first()
            product = Product.query.filter_by(product_id=cartitem.product_id).first()

            if not cartitem:
                return jsonify(message="Cart item does not exist"), 404

            else:
                # Product quantity
                cartitem.product_quantity = int(req_data['product_quantity'])

                if cartitem.product_size == "XS":
                    avail_stock = product.size_XS

                elif cartitem.product_size == "S":
                    avail_stock = product.size_S

                elif cartitem.product_size == "M":
                    avail_stock = product.size_M

                elif cartitem.product_size == "L":
                    avail_stock = product.size_L

                elif cartitem.product_size == "XL":
                    avail_stock = product.size_XL

                if cartitem.product_quantity > avail_stock:
                    result = "Current stock level: " + str(product.size_XS)
                    return jsonify(message="Insufficient quantity", data=result), 409

                # Product price
                cartitem.product_price = product.product_price

                if status == 'valid':
                    # db.session.commit()
                    result = cart_item_schema.dump(cartitem)

                    # Update login user "last_active" value
                    login_customer.last_active = datetime.today()
                    db.session.commit()

                    return jsonify(message="Cart item updated", data=result), 202

        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/delete_cartitem/<int:id>', methods=['DELETE'])
@jwt_required
@limiter.limit('default_limits')
def delete_cartitem(id: int):
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()
    customer = Customer.query.filter_by(customer_id=login_customer.user_id).first()

    username = get_jwt_identity()
    if username != customer.customer_email:
        return jsonify(message="Invalid Token"), 401

    if login_customer:
        '''
        if check_last_active(login_customer.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_customer.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_customer.user_role == "customer":
            cartitem = Customer_Cart.query.filter_by(cartitem_id=id).first()

            if cartitem:
                db.session.delete(cartitem)
                # db.session.commit()

                # Update login user "last_active" value
                login_customer.last_active = datetime.today()
                db.session.commit()

                return jsonify(message="Cart item deleted"), 202

            else:
                return jsonify(message="Cart item does not exist"), 404
        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# ================================== CHECKOUT ==================================

@app.route('/checkout', methods=['POST'])
@jwt_required
@limiter.limit('default_limits')
def checkout():
    req_data = request.get_json()

    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()
    customer = Customer.query.filter_by(customer_id=login_customer.user_id).first()

    username = get_jwt_identity()
    if username != customer.customer_email:
        return jsonify(message="Invalid Token"), 401

    if login_customer:
        '''
        if check_last_active(login_customer.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_customer.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_customer.user_role == "customer":
            customer_id = login_customer.user_id

            # Necessary Customer Information
            customer = Customer.query.filter_by(customer_id=customer_id).first()
            customer_name = customer.customer_fname
            email = customer.customer_email

            # Shipping Information
            # Billing Address
            billing_address = req_data['billing_address']
            if billing_address == "":
                return jsonify(message="Field required"), 409

            # Postal Code, Example: 590133
            postal_code = req_data['postal_code']
            x = re.compile(r"^[0-9]{6}$")
            if postal_code.isalpha():
                return jsonify(message="Invalid postal code"), 409
            if postal_code == "":
                return jsonify(message="Field required"), 409
            if not x.findall(postal_code):
                return jsonify(message="Invalid postal code"), 409

            postal_code = int(postal_code)

            # Shipping Method
            method = {1: "Standard Delivery", 2: "Express Delivery"}
            try:
                shipping_method = int(req_data['shipping_method'])
                if shipping_method not in method:
                    return jsonify(message="Method does not exist"), 409
                elif shipping_method == "":
                    return jsonify(message="Field required"), 409
            except ValueError:
                return jsonify(message="Method does not exist"), 409

            # Combine address and postal code together to store in db
            address = billing_address + " S({})".format(postal_code)

            # Card Information
            # Card Types
            card_types = {1: "MasterCard", 2: "Visa", 3: "American Express"}
            try:
                card_type = int(req_data['card_type'])

                if card_type not in card_types:
                    return jsonify(message="Invalid card type"), 409

                # MasterCard, Example: 5335069617491253
                elif card_type == 1:
                    card_number = req_data['card_number']
                    x = re.compile(
                        r"^(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))$")
                    if card_number.isalpha():
                        return jsonify(message="Invalid MasterCard number"), 409
                    elif card_number == '':
                        return jsonify(message="Field required"), 409
                    if not x.findall(card_number):
                        return jsonify(message="Invalid MasterCard number"), 409

                # Visa, Example: 4893976881588910
                elif card_type == 2:
                    card_number = req_data['card_number']
                    x = re.compile(r"^4[0-9]{12}(?:[0-9]{3})?$")
                    if card_number.isalpha():
                        return jsonify(message="Invalid Visa card number"), 409
                    elif card_number == '':
                        return jsonify(message="Field required"), 409
                    if not x.findall(card_number):
                        return jsonify(message="Invalid Visa card number"), 409

                # American Express, Example: 372620983015392
                elif card_type == 3:
                    card_number = req_data['card_number']
                    x = re.compile(r"^3[47][0-9]{13}$")
                    if card_number.isalpha():
                        return jsonify(message="Invalid American Express card number"), 409
                    elif card_number == '':
                        return jsonify(message="Field required"), 409
                    if not x.findall(card_number):
                        return jsonify(message="Invalid American Express card number"), 409

                elif card_type == '':
                    return jsonify(message="Field required"), 409

            except ValueError:
                return jsonify(message="Card type does not exist"), 409

            # Expiry Date MM/YY, Example: 04/22
            expiry_date = req_data['expiry_date']
            x = re.compile(r"^(0[1-9]|10|11|12)\/[0-9]{2}$")
            if expiry_date.isalpha():
                return jsonify(message="Invalid expiry date"), 409
            elif expiry_date == "":
                return jsonify(message="Field required"), 409
            if not x.findall(expiry_date):
                return jsonify(message="Invalid expiry date"), 409

            # Verification Number, Example: 123
            verification_number = req_data['verification_number']
            x = re.compile(r"^[0-9]\d\d$")
            if verification_number.isalpha():
                return jsonify(message="Invalid verification number"), 409
            elif verification_number == "":
                return jsonify(message="Field required"), 409
            if not x.findall(verification_number):
                return jsonify(message="Invalid verification number"), 409

            # Product Quantity Deduction
            login_customer = Login_Info.query.filter_by(login_id=1).first()

            cart_list = Customer_Cart.query.filter_by(customer_id=login_customer.user_id).all()
            if len(cart_list) != 0:
                products_list = Product.query.all()
                for i in products_list:
                    product = i.product_id

                    for x in cart_list:
                        item = x.product_id
                        size = x.product_size
                        quantity = x.product_quantity

                        if product == item:
                            product = Product.query.filter_by(product_id=product).first()
                            if size == "XS":
                                product.size_XS -= quantity
                                db.session.commit()

                            elif size == "S":
                                product.size_S -= quantity
                                db.session.commit()

                            elif size == "M":
                                product.size_M -= quantity
                                db.session.commit()

                            elif size == "L":
                                product.size_L -= quantity
                                db.session.commit()

                            elif size == "XL":
                                product.size_XL -= quantity
                                db.session.commit()

                receipt = Customer_Receipt(
                    customer_id=login_customer.user_id,
                    customer_address=address,
                    shipping_method=method[shipping_method],
                    checkout_date=str(datetime.today().replace(second=0, microsecond=0)),
                )

                db.session.add(receipt)
                db.session.commit()

                for x in cart_list:
                    confirmed_order = Confirmed_Order(order_id=receipt.receipt_id,
                                                      product_id=x.product_id,
                                                      product_size=x.product_size,
                                                      product_price=x.product_price,
                                                      product_quantity=x.product_quantity,
                                                      customer_id=login_customer.user_id)

                    db.session.add(confirmed_order)
                    db.session.delete(x)

                confirmed_list = Confirmed_Order.query.filter_by(order_id=receipt.receipt_id).all()
                confirmed = cart_items_schema.dump(confirmed_list)

                db.session.commit()

                receipt_id = receipt.receipt_id
                order_date = receipt.checkout_date

                # Generate receipt message
                print_receipt = {
                    'Customer Name': '{}'.format(customer_name),
                    'Receipt Id': '{}'.format(receipt_id),
                    'Shipping Address': '{}'.format(address),
                    'Shipping Method': '{}'.format(method[shipping_method]),
                    'Order Date': '{}'.format(order_date)}

                print_items = []
                email_items = []
                total = 0
                shipping_fee = 0
                for a in confirmed:
                    prod_id = a["product_id"]
                    prod_name = Product.query.filter_by(product_id=prod_id).first().product_name
                    prod_size = a["product_size"]
                    prod_quantity = a["product_quantity"]
                    prod_price = a["product_price"]
                    sub_total = prod_quantity * prod_price
                    prod_desc = Product.query.filter_by(product_id=prod_id).first().product_description
                    total = total + sub_total

                    instance = {
                        'Product Name': '{}'.format(prod_name),
                        'Product Size': '{}'.format(prod_size),
                        'Product Quantity': '{}'.format(prod_quantity),
                        'Product Price': 'S${:.2f}'.format(prod_price),
                        'Product Description': '{}'.format(prod_desc),
                        'Sub-Total': 'S${:.2f}'.format(sub_total)}

                    print_items.append(instance)
                    msg = "Product Name: {} \nDescription: {} \nSize: {} \nQuantity: {} \nPrice: S${:.2f} \nSub-total: S${:.2f}".format(
                        str(prod_name), str(prod_desc), str(prod_size), str(prod_quantity), prod_price, sub_total)
                    email_items.append(msg)

                # Add customer points
                customer.customer_points += int(total // 1)
                db.session.commit()

                if shipping_method == 2:
                    shipping_fee = 5.00
                    total += shipping_fee

                # Order Confirmed Email
                msg = Message("Order Confirmed [#" + str(receipt_id) + "]",
                              sender=app.config['MAIL_FROM_EMAIL'],
                              recipients=[email])

                msg.body = 'Hi {}, \n\nYour order has been confirmed. Please ensure that all the information below are correct. For changes, please email us at: glomz@store-api.com'.format(
                    customer_name) \
                           + '\n\n--- ORDER DETAILS --- \nOrder Number: #{} \nOrder Date: {} \nShipping Address: {}'.format(
                    str(receipt_id), str(order_date), str(address)) \
                           + '\n\n==============================================================================\n\n' \
                           + '\n\n'.join((map(str, email_items))) \
                           + '\n\n==============================================================================' \
                           + '\n\nShipping Fee: S${:.2f}'.format(shipping_fee) \
                           + '\nTotal Amount: S${:.2f}'.format(total)

                mail.send(msg)

                # Update login user "last_active" value
                login_customer.last_active = datetime.today()
                db.session.commit()

                return jsonify({'Receipt': print_receipt}, {'Items': print_items}, {'Total': 'S${:.2f}'.format(total)})

            else:
                return jsonify(message="Cart is empty"), 409
    else:
        return jsonify(message="No login user"), 404  # user must log in first to checkout, 409


@app.route('/view_orders')
@jwt_required
@limiter.limit('default_limits')
def view_orders():
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()
    customer = Customer.query.filter_by(customer_id=login_customer.user_id).first()

    username = get_jwt_identity()
    if username != customer.customer_email:
        return jsonify(message="Invalid Token"), 401

    if login_customer:
        '''
        if check_last_active(login_customer.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_customer.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_customer.user_role == "customer":
            customer_orders = Confirmed_Order.query.filter_by(customer_id=login_customer.user_id).all()
            result = confirmed_orders_schema.dump(customer_orders)
            print_items = []
            for i in result:
                receipt_id = i['order_id']
                prod_id = i["product_id"]
                product_name = Product.query.filter_by(product_id=prod_id).first().product_name
                product_price = i['product_price']
                product_quantity = i['product_quantity']
                product_size = i['product_size']

                instance = {
                    'Receipt Id': '{}'.format(receipt_id),
                    'Product Name': '{}'.format(product_name),
                    'Product Price': '{}'.format(product_price),
                    'Product Quantity': '{}'.format(product_quantity),
                    'Product Size': '{}'.format(product_size),

                }
                print_items.append(instance)

            # Update login user "last_active" value
            login_customer.last_active = datetime.today()
            db.session.commit()

            return jsonify(Items=print_items)

        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# Load product picture
# http://127.0.0.1:5005/loadImage?id=01
@app.route('/loadImage')
@jwt_required
@limiter.limit('default_limits')
def loadImage():
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()
    customer = Customer.query.filter_by(customer_id=login_customer.user_id).first()

    username = get_jwt_identity()
    if username != customer.customer_email:
        return jsonify(message="Invalid Token"), 401

    if login_customer:
        '''
        if check_last_active(login_customer.last_active) > 600:  # Checks for inactivity for 10 minutes
            return jsonify(message="Session timeout"), 440
        '''

        if login_customer.confirmed == "":
            return jsonify(message="Login not successful"), 403  # Need to complete two-step verification

        if login_customer.user_role == "customer":

            images = {
                "01": os.path.realpath(os.getcwd() + '/etc/images/pants.jpg'),
                "02": os.path.realpath(os.getcwd() + '/etc/images/shirt.jpg')
            }
            image_id = request.args.get('id')
            if not image_id:
                return jsonify(message="Image not found"), 404
            elif image_id not in images:
                return jsonify(message="Image not found"), 404

            # Update login user "last_active" value
            login_customer.last_active = datetime.today()
            db.session.commit()

            return send_file(images[image_id])

        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# ================================== DATABASE MODELS ==================================

class Product(db.Model):
    __tablename__ = 'products'
    product_id = Column(Integer, primary_key=True)
    product_name = Column(String)  # unique=True
    product_category = Column(String)
    product_price = Column(Float)
    product_description = Column(String)
    size_XS = Column(Integer)
    size_S = Column(Integer)
    size_M = Column(Integer)
    size_L = Column(Integer)
    size_XL = Column(Integer)


class Customer(db.Model):
    __tablename__ = 'customer'
    customer_id = Column(Integer, primary_key=True)
    customer_fname = Column(String)
    customer_lname = Column(String)
    customer_gender = Column(String)
    customer_email = Column(String)  # unique=True
    customer_phone = Column(Integer)  # unique=True
    customer_points = Column(Integer)
    customer_password = Column(String)
    registered_on = Column(String)
    confirmed_on = Column(String)
    login_tries = Column(Integer)


class Staff(db.Model):
    __tablename__ = 'staff'
    staff_id = Column(Integer, primary_key=True)
    staff_fname = Column(String)
    staff_lname = Column(String)
    staff_gender = Column(String)
    staff_email = Column(String)  # unique=True
    staff_phone = Column(Integer)  # unique=True
    staff_position = Column(String)
    staff_password = Column(String)
    login_tries = Column(Integer)


class Customer_Cart(db.Model):
    __tablename__ = 'customer_cart'
    cartitem_id = Column(Integer, primary_key=True)
    product_id = Column(Integer)
    product_size = Column(String)
    product_price = Column(Float)
    product_quantity = Column(Integer)
    customer_id = Column(Integer)


class Confirmed_Order(db.Model):
    __tablename__ = 'confirmed_order'
    table_id = Column(Integer, primary_key=True)
    order_id = Column(Integer)
    product_id = Column(Integer)
    product_size = Column(String)
    product_price = Column(Float)
    product_quantity = Column(Integer)
    customer_id = Column(Integer)


class Customer_Receipt(db.Model):
    __tablename__ = 'customer_receipt'
    receipt_id = Column(Integer, primary_key=True)
    customer_id = Column(String)
    customer_address = Column(String)
    shipping_method = Column(String)
    checkout_date = Column(String)


class Login_Info(db.Model):
    __tablename__ = 'login_info'
    login_id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    user_role = Column(String)
    last_active = Column(String)
    code = Column(Integer)
    code_created = Column(String)
    confirmed = Column(String)


class ProductSchema(ma.Schema):
    class Meta:
        fields = (
            'product_id', 'product_name', 'product_category', 'product_price', 'product_description', 'size_XS',
            'size_S', 'size_M', 'size_L', 'size_XL')


class CustomerSchema(ma.Schema):
    class Meta:
        fields = (
            'customer_id', 'customer_fname', 'customer_lname', 'customer_gender', 'customer_email', 'customer_phone',
            'customer_points', 'customer_password', 'registered_on', 'confirmed_on', 'login_tries')


class StaffSchema(ma.Schema):
    class Meta:
        fields = (
            'staff_id', 'staff_fname', 'staff_lname', 'staff_gender', 'staff_email', 'staff_phone', "staff_position",
            "staff_password")


class CustomerCartSchema(ma.Schema):
    class Meta:
        fields = ('cartitem_id', 'product_id', 'product_size', 'product_price', 'product_quantity', 'customer_id')


class ConfirmedOrderSchema(ma.Schema):
    class Meta:
        fields = (
            'table_id', 'order_id', 'product_id', 'product_size', 'product_price', 'product_quantity', 'customer_id')


class CustomerReceiptSchema(ma.Schema):
    class Meta:
        fields = ('receipt_id', 'customer_id', 'customer_address', 'shipping_method', 'checkout_date')


class LoginInfoSchema(ma.Schema):
    class Meta:
        fields = ('login_id', 'user_id', 'user_role', 'last_active', 'code', 'code_created', 'confirmed')


product_schema = ProductSchema()
products_schema = ProductSchema(many=True)

customer_schema = CustomerSchema()
customers_schema = CustomerSchema(many=True)

staff_schema = StaffSchema()
staffs_schema = StaffSchema(many=True)

cart_item_schema = CustomerCartSchema()
cart_items_schema = CustomerCartSchema(many=True)

confirmed_orders_schema = ConfirmedOrderSchema(many=True)

customer_receipt_schema = CustomerReceiptSchema()
customer_receipts_schema = CustomerReceiptSchema(many=True)

login_info_schema = LoginInfoSchema()

if __name__ == '__main__':
    app.run(port=5005, ssl_context='adhoc')
