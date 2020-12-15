# VULNERABLE 23/7/20 2130h

# Re-added Reset Password Function

import os
import re

from flask import Flask, jsonify, request, send_file, render_template, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_mail import Mail, Message
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float
from datetime import datetime
from flask_rest_paginate import Pagination
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))

app.config.update(
    DEBUG=True,
    ENV="development",

    # Database config
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'store.db'),

    # Authentication Config
    JWT_SECRET_KEY='project-store',
    JWT_ACCESS_TOKEN_EXPIRES=1000,
    JWT_BLACKLIST_ENABLED=True,
    JWT_BLACKLIST_TOKEN_CHECKS=['access'],

    # Mail config
    MAIL_SERVER='smtp.mailtrap.io',
    MAIL_PORT=2525,
    MAIL_USERNAME='12dbf006d8cf45',
    MAIL_PASSWORD='7c418e544b23d6',
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=False,
    MAIL_FROM_EMAIL='glomz@store-api.com',

    SECRET_KEY='password',
    SECURITY_PASSWORD_SALT='passwordsalt'
)

blacklist = set()

db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)
mail = Mail(app)

pagination = Pagination(app, db)


@app.route('/', methods=['GET', 'POST'])
def homepage():
    return render_template('test.html')


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


@app.cli.command('db_create')
def db_create():
    db.create_all()
    print('Database Created!')


@app.cli.command('db_drop')
def db_drop():
    db.drop_all()
    print('Database Dropped!')


@app.cli.command('db_seed')
def db_seed():
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
                         size_XL=500)

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

    customer1 = Customer(customer_fname="Test",
                         customer_lname="1",
                         customer_gender="Male",
                         customer_email="test1@gmail.com",
                         customer_phone=92783652,
                         customer_points=0,
                         customer_password="test1")

    customer2 = Customer(customer_fname="Test",
                         customer_lname="2",
                         customer_gender="Female",
                         customer_email="test2@gmail.com",
                         customer_phone=93829173,
                         customer_points=0,
                         customer_password="test2")

    customer3 = Customer(customer_fname="Test",
                         customer_lname="3",
                         customer_gender="Others",
                         customer_email="test3@gmail.com",
                         customer_phone=83782983,
                         customer_points=0,
                         customer_password="test3")

    db.session.add(customer1)
    db.session.add(customer2)
    db.session.add(customer3)

    staff1 = Staff(staff_fname="Gianni",
                   staff_lname="Spencer",
                   staff_email="gianni@business.com",
                   staff_gender="Female",
                   staff_phone=92837182,
                   staff_position="Customer Representative",  # Manage Customers
                   staff_password="bizgianni"
                   )

    staff2 = Staff(staff_fname="Michael",
                   staff_lname="Lin",
                   staff_email="michael@business.com",
                   staff_gender="Male",
                   staff_phone=83782918,
                   staff_position="Product Manager",          # Manage Products
                   staff_password="bizmichael"
                   )

    staff3 = Staff(staff_fname="Eden",
                   staff_lname="Estes",
                   staff_email="eden@business.com",
                   staff_gender="Female",
                   staff_phone=84937823,
                   staff_position="CEO",                      # Root Access
                   staff_password="bizeden"
                   )

    db.session.add(staff1)
    db.session.add(staff2)
    db.session.add(staff3)

    db.session.commit()
    print('Database Seeded!')


# ================================== PRODUCT ==================================

@app.route('/products')
@jwt_required
def products():
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            products_list = Product.query.all()
            result = products_schema.dump(products_list)
            return jsonify(message="Products retrieved", data=result)
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/product_details/<int:product_id>')
@jwt_required
def product_details(product_id: int):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            product = Product.query.filter_by(product_id=product_id).first()
            if product:
                result = product_schema.dump(product)
                return jsonify(message="Product retrieved", data=result)
            else:
                return jsonify(message="Product does not exist"), 404
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/add_product', methods=['POST'])
@jwt_required
def add_product():
    req_data = request.get_json()

    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            product_name = req_data['product_name']  # need put validation e.g. vulnerable to injection
            if product_name == "":
                return jsonify(message="Field required"), 409
            test = Product.query.filter_by(product_name=product_name).first()
            if test:
                return jsonify(message="Product name exists"), 409
            else:
                # Category
                category = {1: "Men's Top", 2: "Men's Bottom", 3: "Men's Shoes", 4: "Men's Accessories", 5: "Women's Top", 6: "Women's Bottom", 7: "Women's Shoes", 8: "Women's Accessories"}
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

                new_product = Product(product_name=product_name,
                                      product_category=category[product_category],
                                      product_price=product_price,
                                      product_description=product_description,
                                      size_XS=size_XS,
                                      size_S=size_S,
                                      size_M=size_M,
                                      size_L=size_L,
                                      size_XL=size_XL)

                db.session.add(new_product)
                db.session.commit()

                result = product_schema.dump(new_product)
                return jsonify(message="Product added", data=result), 201
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/update_product', methods=['PUT'])
@jwt_required
def update_product():
    req_data = request.get_json()

    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
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
                category = {1: "Men's Top", 2: "Men's Bottom", 3: "Men's Shoes", 4: "Men's Accessories", 5: "Women's Top", 6: "Women's Bottom", 7: "Women's Shoes", 8: "Women's Accessories"}
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

                db.session.commit()
                result = product_schema.dump(product)
                return jsonify(message="Product updated", data=result), 202

            else:
                return jsonify(message="Product does not exist"), 404
        else:
            return jsonify(message="Customers not permitted"), 404
    else:
        return jsonify(message="No login user"), 404


@app.route('/delete_product/<product_id>', methods=['DELETE'])
@jwt_required
def delete_product(product_id):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            query = f"SELECT product_id FROM products WHERE product_id = '{product_id}'"
            products_id = db.session.execute(query).fetchall()
            if products_id:
                query = f"DELETE FROM products WHERE product_id = '{product_id}' "
                db.session.execute(query)
                db.session.commit()
                return jsonify(message="Product deleted"), 202
            else:
                return jsonify(message="Product ID does not exist"), 404
        else:
            return jsonify(message="Customers not permitted"), 404
    else:
        return jsonify(message="No login user"), 404


# Vulnerable paginated products page
# Example: http://127.0.0.1:5005/products_page/?size=20&page=1
# Size refers to number of products shown per page and Page represents that page number.
@app.route('/products_page/', methods=['GET'])
@jwt_required
def products_page():
    result = pagination.paginate(Product, products_schema, True)
    return jsonify(result)


# ================================== CUSTOMERS ==================================

# For staff to view all customers
@app.route('/customers')
@jwt_required
def customers():
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            customers_list = Customer.query.all()
            result = customers_schema.dump(customers_list)
            return jsonify(message="Customers retrieved", data=result), 200
        else:
            return jsonify(message="Customers not permitted"), 404
    else:
        return jsonify(message="No login user"), 404


# For customer to view their own details
@app.route('/customer_details/<int:customer_id>', methods=['GET'])
@jwt_required
def customer_details(customer_id: int):
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
        if login_customer.user_role == "customer":
            customer = Customer.query.filter_by(customer_id=customer_id).first()
            if customer:
                result = customer_schema.dump(customer)
                return jsonify(message="Customer retrieved", data=result), 200
            else:
                return jsonify(message="Customer does not exist"), 403
        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# For staff to update customer details
@app.route('/update_customer', methods=['PUT'])
@jwt_required
def update_customer():
    req_data = request.get_json()

    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            try:
                customer_id = int(req_data['customer_id'])
            except ValueError:
                return jsonify(message="Invalid customer ID"), 404

            customer = Customer.query.filter_by(customer_id=customer_id).first()

            if customer:
                # Email
                customer.customer_email = req_data['customer_email']
                if customer.customer_email == "":
                    return jsonify(message="Field required"), 409
                elif not (re.search(r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", customer.customer_email)):
                    return jsonify(message="Invalid email"), 409

                email_exists = Customer.query.filter_by(customer_email=customer.customer_email).all()
                if len(email_exists) > 1:
                    return jsonify(message="Email exists"), 409

                # First Name
                customer.customer_fname = req_data['customer_fname']
                if customer.customer_fname == "":
                    return jsonify(message="Field required"), 409
                elif not customer.customer_fname.isalpha():
                    return jsonify(message="Invalid first name"), 409

                # Last Name
                customer.customer_lname = req_data['customer_lname']
                if customer.customer_lname == "":
                    return jsonify(message="Field required"), 409
                elif not customer.customer_lname.isalpha():
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
                customer.customer_phone = req_data['customer_phone']
                if customer.customer_phone == "":
                    return jsonify(message="Field required"), 409
                x = re.compile(r"^[6|8|9]\d{7}$")  # check for valid singapore phone number
                if customer.customer_phone.isalpha():
                    return jsonify(message="Invalid phone number"), 409
                if not x.findall(customer.customer_phone):
                    return jsonify(message="Invalid phone number"), 409
                phone_exists = Customer.query.filter_by(customer_phone=customer.customer_phone).all()
                if len(phone_exists) > 1:
                    return jsonify(message="Phone number exists"), 409

                customer.customer_phone = int(customer.customer_phone)

                customer.customer_password = req_data['customer_password']  # added for mass assignment

                try:
                    customer.customer_points = int(req_data['customer_points'])
                    if customer.customer_points == "":
                        return jsonify(message="Field required"), 409
                except ValueError:
                    return jsonify(message="Invalid points"), 409

                db.session.commit()

                result = customer_schema.dump(customer)
                return jsonify(message="Customer updated", data=result), 202

            else:
                return jsonify(message="Customer does not exist"), 404
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# For customer to update customer details
@app.route('/update_details', methods=['PUT'])
@jwt_required
def update_details():
    req_data = request.get_json()

    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
        if login_customer.user_role == "customer":
            customer = Customer.query.filter_by(customer_id=login_customer.user_id).first()

            try:
                customer_id = int(req_data['customer_id'])
                if customer.customer_id == "":
                    return jsonify(message="Field required"), 409
            except ValueError:
                return jsonify(message="Invalid customer ID"), 404

            customer = Customer.query.filter_by(customer_id=customer_id).first()

            if customer:
                # Email
                customer.customer_email = req_data['customer_email']
                if customer.customer_email == "":
                    return jsonify(message="Field required"), 409
                elif not (re.search(r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", customer.customer_email)):
                    return jsonify(message="Invalid email"), 409
                email_exists = Customer.query.filter_by(customer_email=customer.customer_email).all()
                if len(email_exists) > 1:
                    return jsonify(message="Email exists"), 409

                # First Name
                customer.customer_fname = req_data['customer_fname']
                if customer.customer_fname == "":
                    return jsonify(message="Field required"), 409
                elif not customer.customer_fname.isalpha():
                    return jsonify(message="Invalid first name"), 409

                # Last Name
                customer.customer_lname = req_data['customer_lname']
                if customer.customer_fname == "":
                    return jsonify(message="Field required"), 409
                elif not customer.customer_lname.isalpha():
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
                customer.customer_phone = req_data['customer_phone']
                if customer.customer_phone == "":
                    return jsonify(message="Field required"), 409
                x = re.compile(r"^[6|8|9]\d{7}$")  # check for valid singapore phone number
                if customer.customer_phone.isalpha():
                    return jsonify(message="Invalid phone number"), 409
                if not x.findall(customer.customer_phone):
                    return jsonify(message="Invalid phone number"), 409

                phone_exists = Customer.query.filter_by(customer_phone=customer.customer_phone).all()
                if len(phone_exists) > 1:
                    return jsonify(message="Phone number exists"), 409

                customer.customer_phone = int(customer.customer_phone)

                customer.customer_password = req_data['customer_password']

                try:
                    customer.customer_points = int(req_data['customer_points'])  # added for mass assignment
                    if customer.customer_points == "":
                        return jsonify(message="Field required"), 409
                except ValueError:
                    return jsonify(message="Invalid points"), 409

                db.session.commit()

                result = customer_schema.dump(customer)
                return jsonify(message="Customer updated", data=result), 202

            else:
                return jsonify(message="Customer does not exist"), 404
        else:
            return jsonify(message="Staff not permitted"), 404
    else:
        return jsonify(message="No login user"), 404


@app.route('/delete_customer/<int:customer_id>', methods=['DELETE'])
@jwt_required
def delete_customer(customer_id: int):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            customer = Customer.query.filter_by(customer_id=customer_id).first()

            if customer:
                db.session.delete(customer)
                db.session.commit()
                return jsonify(message="Customer deleted"), 202

            else:
                return jsonify(message="Customer does not exist"), 404
        else:
            return jsonify(message="Customers not permitted"), 404
    else:
        return jsonify(message="No login user"), 404


# ================================== STAFF ==================================

@app.route('/staffs')
@jwt_required
def staffs():
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            staffs_list = Staff.query.all()
            result = staffs_schema.dump(staffs_list)
            return jsonify(message="Staff retrieved", data=result)
        else:
            return jsonify(message="Customers not permitted"), 404
    else:
        return jsonify(message="No login user"), 404


@app.route('/staff_details/<int:staff_id>')
@jwt_required
def staff_details(staff_id: int):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            staff = Staff.query.filter_by(staff_id=staff_id).first()

            if staff:
                result = staff_schema.dump(staff)
                return jsonify(message="Staff retrieved", data=result), 200

            else:
                return jsonify(message="Staff does not exist"), 404
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/create_staff', methods=['POST'])
@jwt_required
def create_staff():
    req_data = request.get_json()

    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            # Email
            staff_email = req_data['staff_email']
            if staff_email == "":
                return jsonify(message="Field required"), 409

            elif not (re.search(r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", staff_email)):
                return jsonify(message="Invalid email"), 409

            staff_check = Staff.query.filter_by(staff_email=staff_email).first()

            if not staff_check:
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
                x = re.compile(r"^[6|8|9]\d{7}$")  # check for valid singapore phone number
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

                staff_phone = int(staff_phone)

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

                new_staff = Staff(staff_fname=staff_fname,
                                  staff_lname=staff_lname,
                                  staff_gender=gender[staff_gender],
                                  staff_email=staff_email,
                                  staff_phone=staff_phone,
                                  staff_position=position[staff_position],
                                  staff_password=staff_password)

                db.session.add(new_staff)
                db.session.commit()
                result = staff_schema.dump(new_staff)

                return jsonify(message="Staff created", data=result), 201

            else:
                return jsonify(message="Email registered"), 409
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/update_staff', methods=['PUT'])
@jwt_required
def update_staff():
    req_data = request.get_json()

    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            try:
                staff_id = int(req_data['staff_id'])
                if staff_id == "":
                    return jsonify(message="Field required"), 409
            except ValueError:
                return jsonify(message="Invalid staff ID"), 409

            staff = Staff.query.filter_by(staff_id=staff_id).first()

            if staff:
                # Email
                staff.staff_email = req_data['staff_email']

                if staff.staff_email == "":
                    return jsonify(message="Field required"), 409

                elif not (re.search(r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", staff.staff_email)):
                    return jsonify(message="Invalid email"), 409

                email_exists = Staff.query.filter_by(staff_email=staff.staff_email).all()
                if len(email_exists) > 1:
                    return jsonify(message="Email exists"), 409

                # First Name
                staff.staff_fname = req_data['staff_fname']

                if staff.staff_fname == "":
                    return jsonify(message="Field required"), 409

                elif not staff.staff_fname.isalpha():
                    return jsonify(message="Invalid first name"), 409

                # Last Name
                staff.staff_lname = req_data['staff_lname']

                if staff.staff_lname == "":
                    return jsonify(message="Field required"), 409

                elif not staff.staff_lname.isalpha():
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
                staff.staff_phone = req_data['staff_phone']

                if staff.staff_phone == "":
                    return jsonify(message="Field required"), 409

                x = re.compile(r"^[6|8|9]\d{7}$")  # check for valid singapore phone number

                if staff.staff_phone.isalpha():
                    return jsonify(message="Invalid phone number"), 409

                if not x.findall(staff.staff_phone):
                    return jsonify(message="Invalid phone number"), 409

                phone_exists = Staff.query.filter_by(staff_phone=staff.staff_phone).all()
                if len(phone_exists) > 1:
                    return jsonify(message="Phone number exists"), 409

                staff.staff_phone = int(staff.staff_phone)

                # Position
                position = {1: "CEO", 2: "Customer Representative", 3: "Product Manager"}

                try:
                    staff.staff_position = int(req_data['staff_position'])  # added for mass assignment

                    if staff.staff_position == "":
                        return jsonify(message="Field required"), 409

                    elif staff.staff_position not in position:
                        return jsonify(message="Staff position does not exist"), 409

                    else:
                        staff.staff_position = position[staff.staff_position]

                except ValueError:
                    return jsonify(message="Staff position does not exist"), 409

                # Password
                staff.staff_password = req_data['staff_password']  # added for mass assignment

                if staff.staff_password == "":
                    return jsonify(message="Field required"), 409

                db.session.commit()
                result = staff_schema.dump(staff)
                return jsonify(message="Staff updated", data=result), 202

            else:
                return jsonify(message="Staff does not exist"), 404
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/delete_staff/<int:staff_id>', methods=['DELETE'])
@jwt_required
def delete_staff(staff_id: int):
    # Login staff information
    login_staff = Login_Info.query.filter_by(login_id=1).first()

    if login_staff:
        if login_staff.user_role == "staff":
            staff = Staff.query.filter_by(staff_id=staff_id).first()

            if staff_id == 3:
                return jsonify(message="eden@business.com cannot be removed"), 403

            elif staff_id == login_staff.user_id:
                return jsonify(message="You cannot remove yourself"), 403

            elif staff:
                db.session.delete(staff)
                db.session.commit()
                return jsonify(message="Staff deleted"), 202

            else:
                return jsonify(message="Staff does not exist"), 404
        else:
            return jsonify(message="Customers not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# ================================== REGISTER ==================================

@app.route('/register', methods=['POST'])
def register():
    req_data = request.get_json()

    customer_email = req_data['customer_email']
    customer_email = customer_email.lower()

    if customer_email == "":
        return jsonify(message="Field required"), 409
    elif not (re.search(r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", customer_email)):
        return jsonify(message="Invalid email"), 409

    test = Customer.query.filter_by(customer_email=customer_email).first()
    if test:
        return jsonify(message="Email registered"), 409

    else:
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
        x = re.compile(r"^[6|8|9]\d{7}$")  # check for valid singapore phone number
        if customer_phone == "":
            return jsonify(message="Field required"), 409
        elif customer_phone.isalpha():
            return jsonify(message="Invalid phone number"), 409
        elif not x.findall(customer_phone):
            return jsonify(message="Invalid phone number"), 409

        # Check if the phone number is unique - phone number that exist will show integrity error
        phone_exists = Customer.query.filter_by(customer_phone=customer_phone).all()
        if len(phone_exists) > 1:
            return jsonify(message="Phone number exists"), 409

        customer_phone = int(customer_phone)

        # Password
        customer_password = req_data['customer_password']  # can set password rules e.g. min 7 char blah blah
        if customer_password == "":
            return jsonify(message="Field required"), 409

        new_customer = Customer(customer_fname=customer_fname,
                                customer_lname=customer_lname,
                                customer_gender=gender[customer_gender],
                                customer_email=customer_email,
                                customer_phone=customer_phone,
                                customer_points=0,
                                customer_password=customer_password)

        db.session.add(new_customer)
        db.session.commit()

        # Generate receipt message
        print_info = {
                'FName': '{}'.format(customer_fname),
                'LName': '{}'.format(customer_lname),
                'Gender': '{}'.format(gender[customer_gender]),
                'Email': '{}'.format(customer_email),
                'Phone': '{}'.format(customer_phone),
                'Customer Points': '{}'.format(0),
                'Password': '{}'.format(customer_password)}

        return jsonify(Registered=print_info, message="Account registered"), 201


# ================================== LOGIN ==================================

@app.route('/login', methods=['POST'])
def login():
    req_data = request.get_json()

    # If a user is already logged in, prompt user to log out first
    login_user = Login_Info.query.filter_by(login_id=1).first()

    user_email = req_data['user_email']
    user_password = req_data['user_password']

    # Insecure sql statement that allows attacker to access any customer or staff account with their known email eg. douglas@gmail.com' or '1=1 and any password
    customer_user = db.session.execute(f"SELECT * FROM Customer WHERE customer_email = '{user_email}' AND customer_password = '{user_password}'").first()
    staff_user = db.session.execute(f"SELECT * FROM Staff WHERE staff_email = '{user_email}' AND staff_password = '{user_password}'").first()

    if login_user:
        if login_user.user_role == 'customer':
            current_user = Customer.query.filter_by(customer_id=login_user.user_id).first()
            return jsonify(message="Logged in as " + current_user.customer_email), 403

        elif login_user.user_role == 'staff':
            current_user = Staff.query.filter_by(staff_id=login_user.user_id).first()
            return jsonify(message="Logged in as " + current_user.staff_email), 403

        else:
            logged_in_user = Login_Info(login_id=1, user_id=customer_user.customer_id, user_role='customer')
            db.session.add(logged_in_user)
            db.session.commit()

            access_token = create_access_token(identity=user_email)
            return jsonify(message="Login succeeded", access_token=access_token), 201

    if customer_user:  # If there is a match --> USER IS FOUND
        logged_in_user = Login_Info(login_id=1, user_id=customer_user.customer_id, user_role='customer')
        db.session.add(logged_in_user)
        db.session.commit()

        access_token = create_access_token(identity=user_email)
        return jsonify(message="Login succeeded", access_token=access_token), 201

    elif staff_user:
        logged_in_user = Login_Info(login_id=1, user_id=staff_user.staff_id, user_role='staff')
        db.session.add(logged_in_user)
        db.session.commit()

        access_token = create_access_token(identity=user_email)
        return jsonify(message="Login succeeded", access_token=access_token), 201

    else:
        # Incorrect customer password
        if Customer.query.filter_by(customer_email=user_email).first():
            return jsonify(message="Incorrect password"), 401

        # Incorrect staff password
        elif Staff.query.filter_by(staff_email=user_email).first():
            return jsonify(message="Incorrect password"), 401

        # Incorrect customer email
        elif Customer.query.filter_by(customer_password=user_password).first():
            return jsonify(message="Incorrect email"), 401

        # Incorrect staff email
        elif Staff.query.filter_by(staff_password=user_password).first():
            return jsonify(message="Incorrect email"), 401

        # Incorrect email and password
        else:
            return jsonify(message="Incorrect email and password"), 401  # status code for permission denied


# Endpoint for revoking the current users access token
@app.route('/logout', methods=['DELETE'])
def logout():
    # Empty 'login_info' table
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
        db.session.delete(login_customer)
        db.session.commit()

    return jsonify(message="Logout succeeded"), 202


# ================================== RESET PASSWORD ==================================

# SEND EMAIL, need to be logged in
@app.route('/reset_password_email/<string:customer_email>', methods=['GET'])  # OWEN
def reset_password_email(customer_email: str):
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer.user_role == "customer":
        customer = Customer.query.filter_by(customer_email=customer_email).first()

        if customer:
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


@app.route('/reset_password/<token>')  # OWEN
def reset_password(token):
    req_data = request.get_json()

    try:
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        customer_email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=600)  # valid for 10 minutes
    except SignatureExpired:
        return jsonify(message="The reset link is invalid or has expired."), 401
    customer = Customer.query.filter_by(customer_email=customer_email).first()

    customer.customer_password = req_data['customer_password']
    db.session.commit()
    return jsonify(message="Your password has been reset!"), 202


# ================================== SHOPPING CART ==================================

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@jwt_required
def add_to_cart(product_id: int):
    global message
    req_data = request.get_json()

    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
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

            if cartitem and cartitem.customer_id == login_customer.user_id and cartitem.product_size == size[product_size]:
                return jsonify(message="Cart item exists"), 409

            if status == 'valid':
                new_cart_item = Customer_Cart(product_id=product_id,
                                              product_size=size[product_size],
                                              product_price=product_price,
                                              product_quantity=product_quantity,
                                              customer_id=login_customer.user_id)

                db.session.add(new_cart_item)
                db.session.commit()

                message = "Cart item added"
                result = cart_item_schema.dump(new_cart_item)

            return jsonify(message=message, data=result), 201

        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/shopping_cart', methods=['GET'])
@jwt_required
def shopping_cart():
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
        if login_customer.user_role == "customer":
            login_customer = Login_Info.query.filter_by(login_id=1).first()

            if login_customer:
                cart_list = Customer_Cart.query.filter_by(customer_id=login_customer.user_id).all()
                result = cart_items_schema.dump(cart_list)
                return jsonify(message="Cart retrieved", data=result), 200

            else:
                return jsonify(message="No login customer"), 403
        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/update_cart/<int:id>', methods=['PUT'])
@jwt_required
def update_cart(id: int):
    req_data = request.get_json()

    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
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
                    db.session.commit()
                    result = cart_item_schema.dump(cartitem)
                    return jsonify(message="Cart item updated", data=result), 202

        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


@app.route('/delete_cartitem/<int:id>', methods=['DELETE'])
@jwt_required
def delete_cartitem(id: int):
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
        if login_customer.user_role == "customer":
            cartitem = Customer_Cart.query.filter_by(cartitem_id=id).first()

            if cartitem:
                db.session.delete(cartitem)
                db.session.commit()

                return jsonify(message="Cart item deleted"), 202

            else:
                return jsonify(message="Cart item does not exist"), 404
        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# ================================== CHECKOUT ==================================

card_number = ''


@app.route('/checkout', methods=['POST'])
@jwt_required
def checkout():
    req_data = request.get_json()

    # Login customer information
    global card_number
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
        if login_customer.user_role == "customer":
            customer_id = login_customer.user_id

            # Customer Information
            customer = Customer.query.filter_by(customer_id=customer_id).first()
            customer_name = customer.customer_fname
            email = customer.customer_email
            phone_number = customer.customer_phone

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
                    return jsonify(message="Shipping method does not exist"), 409
                elif shipping_method == "":
                    return jsonify(message="Field required"), 409
            except ValueError:
                return jsonify(message="Shipping method does not exist"), 409

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
                    x = re.compile(r"^(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))$")
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

                receipt = Customer_Receipt(customer_name=customer_name,
                                           customer_id=login_customer.user_id,
                                           customer_email=email,
                                           customer_phone=phone_number,
                                           customer_address=address,
                                           shipping_method=method[shipping_method],
                                           checkout_date=str(datetime.today()),
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
                        'Customer Id': '{}'.format(customer_id),
                        'Receipt Id': '{}'.format(receipt_id),
                        'Email': '{}'.format(email),
                        'Name': '{}'.format(customer_name),
                        'Phone Number': '{}'.format(phone_number),
                        'Shipping Address': '{}'.format(address),
                        'Shipping Method': '{}'.format(method[shipping_method]),
                        'Order Date': '{}'.format(order_date),
                        'Card Type': '{}'.format(card_types[card_type]),
                        'Card Number': '{}'.format(card_number),
                        'Card Expiry Date': '{}'.format(expiry_date)}
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
                    msg = "Product Name: {} \nDescription: {} \nSize: {} \nQuantity: {} \nPrice: S${:.2f} \nSub-total: S${:.2f}".format(str(prod_name), str(prod_desc), str(prod_size), str(prod_quantity), prod_price, sub_total)
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

                msg.body = 'Hi {}, \n\nYour order has been confirmed. Please ensure that all the information below are correct. For changes, please email us at: glomz@store-api.com'.format(customer_name) \
                           + '\n\n--- ORDER DETAILS --- \nOrder Number: #{} \nOrder Date: {} \nShipping Address: {}'.format(str(receipt_id), str(order_date), str(address)) \
                           + '\n\n--- PAYMENT INFORMATION --- \nPayment Method: {} \nCard Number: {} \nCard Expiry Date: {}'.format(str(card_types[card_type]), str(card_number), str(expiry_date)) \
                           + '\n\n==============================================================================\n\n' \
                           + '\n\n'.join((map(str, email_items))) \
                           + '\n\n==============================================================================' \
                           + '\n\nShipping Fee: S${:.2f}'.format(shipping_fee) \
                           + '\nTotal Amount: S${:.2f}'.format(total)

                mail.send(msg)

                return jsonify({'Receipt': print_receipt}, {'Items': print_items}, {'Total': 'S${:.2f}'.format(total)}), 201

            else:
                return jsonify(message="Cart is empty"), 404
    else:
        return jsonify(message="No login user"), 404  # user must login first to checkout, 404


@app.route('/view_orders')
@jwt_required
def view_orders():
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
        if login_customer.user_role == "customer":
            customer_orders = Confirmed_Order.query.filter_by(customer_id=login_customer.user_id).all()
            result = confirmed_orders_schema.dump(customer_orders)
            return jsonify(message="Orders retrieved", data=result)
        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# Load product picture
# http://127.0.0.1:5005/loadImage?filename=etc/images/pants.jpg
@app.route('/loadImage')
@jwt_required
def loadImage():
    # Login customer information
    login_customer = Login_Info.query.filter_by(login_id=1).first()

    if login_customer:
        if login_customer.user_role == "customer":
            image_name = request.args.get('filename')
            if not image_name:
                return jsonify(message="Picture not found"), 404
            return send_file(os.path.join(os.getcwd(), image_name))
        else:
            return jsonify(message="Staff not permitted"), 403
    else:
        return jsonify(message="No login user"), 404


# ================================== DATABASE MODELS ==================================

class Product(db.Model):
    __tablename__ = 'products'
    product_id = Column(Integer, primary_key=True)
    product_name = Column(String)   # unique=True
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
    customer_email = Column(String)     # unique=True
    customer_phone = Column(Integer)    # unique=True
    customer_points = Column(Integer)
    customer_password = Column(String)


class Staff(db.Model):
    __tablename__ = 'staff'
    staff_id = Column(Integer, primary_key=True)
    staff_fname = Column(String)
    staff_lname = Column(String)
    staff_gender = Column(String)
    staff_email = Column(String)       # unique=True
    staff_phone = Column(Integer)      # unique=True
    staff_position = Column(String)
    staff_password = Column(String)


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
    customer_name = Column(String)
    customer_id =Column(String)
    customer_email = Column(String)
    customer_phone = Column(String)
    customer_address = Column(String)
    shipping_method = Column(String)
    checkout_date = Column(String)


class Login_Info(db.Model):
    __tablename__ = 'login_info'
    login_id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    user_role = Column(String)


class ProductSchema(ma.Schema):
    class Meta:
        fields = ('product_id', 'product_name', 'product_category', 'product_price', 'product_description', 'size_XS', 'size_S', 'size_M', 'size_L', 'size_XL')


class CustomerSchema(ma.Schema):
    class Meta:
        fields = ('customer_id', 'customer_fname', 'customer_lname', 'customer_gender', 'customer_email', 'customer_phone', 'customer_points', 'customer_password')


class StaffSchema(ma.Schema):
    class Meta:
        fields = ('staff_id', 'staff_fname', 'staff_lname', 'staff_gender', 'staff_email', 'staff_phone', "staff_position", "staff_password")


class CustomerCartSchema(ma.Schema):
    class Meta:
        fields = ('cartitem_id', 'product_id', 'product_size', 'product_price', 'product_quantity', 'customer_id')


class ConfirmedOrderSchema(ma.Schema):
    class Meta:
        fields = ('table_id', 'order_id', 'product_id', 'product_size', 'product_price', 'product_quantity', 'customer_id')


class CustomerReceiptSchema(ma.Schema):
    class Meta:
        fields = ('receipt_id', 'customer_name', 'customer_email', 'customer_phone', 'customer_address', 'shipping_method', 'checkout_date', 'customer_id')


class LoginInfoSchema(ma.Schema):
    class Meta:
        fields = ('login_id', 'user_id', 'user_role')


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
    app.run(port=5005)
