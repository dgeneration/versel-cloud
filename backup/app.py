from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask_mail import Mail, Message
from flask_turnstile import Turnstile
import requests
import uuid
import os
import random
import string
from datetime import datetime
from colorama import Fore, Back, Style
from dotenv import load_dotenv, dotenv_values 
from bson import ObjectId

# Loading values from .env file
load_dotenv() 

# Return value from .env file
def env(env_index):
    return os.getenv(env_index)

app = Flask(__name__)
app.secret_key = env('SECRET_KEY')

# Configure Flask-Mail
app.config['MAIL_SERVER'] = env('MAIL_SERVER')
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = env('MAIL_USE_TLS')
app.config['MAIL_USERNAME'] = env('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = env('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = env('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# Configure Flask-Turnstile Cloudflare
app.config['TURNSTILE_ENABLED'] = env('TURNSTILE_ENABLED')
app.config['TURNSTILE_SITE_KEY'] = env('TURNSTILE_SITE_KEY')
app.config['TURNSTILE_SECRET_KEY'] = env('TURNSTILE_SECRET_KEY')

turnstile = Turnstile(app=app)


# MongoDB connection
MONGO_DB_URI = env('MONGO_DB_URI')
MONGO_DB_CLIENT = MongoClient(MONGO_DB_URI, server_api=ServerApi('1'))
MONGO_DB = MONGO_DB_CLIENT['versel_cloud_database']

# MongoDB collection
users_collection = MONGO_DB['users']
transactions_collection = MONGO_DB['transactions']
buy_transactions_collection = MONGO_DB['buy_transactions']

# Send a ping to confirm a successful connection to mongodb server
def check_mongo_db_connection():
    try:
        MONGO_DB_CLIENT.admin.command('ping')
        print(Back.GREEN + "Pinged your deployment. You successfully connected to MongoDB!" + Style.RESET_ALL)
    except Exception as e:
        print(Back.RED + e + Style.RESET_ALL)

# Send a test mail to check mail server connection
@app.route('/check-mail-server-connection', methods=['POST','GET'])
def check_mail_server_connection():
    try:
        msg = Message('Test Email', recipients=['jaypatel252006@gmail.com'])
        msg.body = 'This is a test email to check the mail server connection.'
        mail.send(msg)
        flash('Mail server connection successful. Check your email inbox for the test email.', 'success')
        print(Back.GREEN + f'Mail server connection successful. Check your email inbox for the test email.' + Style.RESET_ALL)
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'Failed to connect to the mail server. Error: {str(e)}', 'danger')
        print(Back.RED + f'Failed to connect to the mail server. Error: {str(e)}' + Style.RESET_ALL)
        return redirect(url_for('login'))

# Get User IP address
def get_user_ip():
    try:
        response = requests.get('https://api64.ipify.org?format=json')
        ip_data = response.json()
        return ip_data['ip']
    except Exception as e:
        print(f"Error retrieving IP address: {e}")
        return None

# Generate verification token
def generate_token():
    return str(uuid.uuid4())

# Send verification email
def send_verification_email(email, token):
    verification_url = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify Your Email',sender=('Versel Cloud', 'support@versel.cloud'), recipients=[email])
    msg.body = f'Please click the following link to verify your email: {verification_url}'
    mail.send(msg)

# Function to generate a unique wallet address
def generate_wallet_address():
    prefix = "0xVC"
    length = 32 - len(prefix)
    random_chars = ''.join(random.choices(string.hexdigits.lower(), k=length))
    return prefix + random_chars

# Function to check if an address is unique in the database
def is_address_unique(address):
    return users_collection.count_documents({"vc_id": address}) == 0

# Function to generate and return a unique wallet address
def generate_unique_address():
    while True:
        address = generate_wallet_address()
        if is_address_unique(address):
            return address
        
# Check if the current user is logged in and is an admin
def is_admin():
    return session.get('username') and users_collection.find_one({'username': session['username'], 'admin': True})

# Function to create transaction history
def create_transaction_history(sender_username,sender_vc_id,recipient_username,recipient_vc_id,amount,note,formatted_datetime,txn_type,credit_type):
    transaction = {
        'sender_username': sender_username,
        'sender_vc_id': sender_vc_id,
        'recipient_username': recipient_username,
        'recipient_vc_id': recipient_vc_id,
        'vc_amount': amount,
        'txn_type': txn_type,
        'credit_type': credit_type,
        'note': note,  # Include the note in the transaction history
        'timestamp': formatted_datetime
    }
    transactions_collection.insert_one(transaction)

# Function to create buy sell transaction history
def create_buy_sell_transaction_history(username,vc_id,vc_amount, pay_amount,note,status,formatted_datetime,txn_type,credit_type):
    buy_transaction = {
        'username': username,
        'vc_id': vc_id,
        'vc_amount': vc_amount,
        'pay_amount': pay_amount,
        'txn_type': txn_type,
        'credit_type': credit_type,
        'note': note,  # Include the note in the transaction history
        'status': status,
        'timestamp': formatted_datetime
    }
    buy_transactions_collection.insert_one(buy_transaction)
     
# Route for the index page
@app.route('/')
def index():
    is_logged_in = 'username' in session
    return render_template('index.html', is_logged_in=is_logged_in)

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']

        # Check if the username and password match

        user = users_collection.find_one({
            '$or': [
                {'username': identifier, 'password': password},
                {'email': identifier, 'password': password},
                {'phone': identifier, 'password': password}
            ]
        })
        if turnstile.verify():
            if user:
                if user.get('email_verified', False):
                    session['username'] = identifier
                    session['ip_address'] = get_user_ip()
                    users_collection.update_one(
                        {'_id': user['_id']},
                        {'$set': {
                            'last_login_ip': get_user_ip()
                        }}
                    )

                    flash('Login successful.', 'success')
                    return redirect(url_for('profile'))
                else:
                    # If email is not verified, resend verification email
                    flash('Your email is not verified. Please check your email for the verification link.', 'warning')
                    send_verification_email(user['email'], user['verification_token'])  # Resend verification email
                    return redirect(url_for('login'))  # Redirect to login page
            else:
                flash('Invalid username or password. Please try again.', 'danger')
        else:
            flash('Captcha is Invalid. Please try again.', 'danger')

    return render_template('login.html')

# Route for the register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        phone = request.form['phone']
        country = request.form['country']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confrim_password = request.form['confirm_password']
        ip_address = get_user_ip()
        verification_token = generate_token()
        wallet_address = generate_unique_address()
        vc_email = username + '@randominfo.blog'
        vc_balance_locked = []
        vc_balance_unlocked = int(0)
        vc_balance_total = int(0)

        if turnstile.verify():
            # Check if the username already exists
            if users_collection.find_one({'$or': [{'username': username}, {'email': email}, {'phone': phone}]}):
                flash('Username, Email, or Phone Number already exists. Choose a different one.', 'danger')
            else:
                if request.form['password'] == request.form['confirm_password']:
                    users_collection.insert_one({
                        'vc_id': wallet_address,
                        'vc_balance_locked': vc_balance_locked, 
                        'vc_balance_unlocked': vc_balance_unlocked, 
                        'vc_balance_total': vc_balance_total, 
                        'username': username, 
                        'password': password, 
                        'email': email, 
                        'email_verified': False, 
                        'vc_email': vc_email.lower(), 
                        'country': country, 
                        'phone': phone, 
                        'first_name': first_name, 
                        'last_name': last_name, 
                        'verification_token': verification_token, 
                        'register_ip': ip_address, 
                        'last_login_ip': ip_address,
                        'admin': False
                    })
                    send_verification_email(email, verification_token)
                    flash('Verification email sent. Please check your inbox.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Password is different from confirm password.', 'danger')
        else:
            flash('Captcha is Invalid. Please try again.', 'danger')
        
    return render_template('register.html')

# Route for the profile page
@app.route('/profile')
def profile():
    is_logged_in = 'username' in session
    if 'username' in session:
        identifier = session['username']
        user = users_collection.find_one({
            '$or': [
                {'username': identifier},
                {'email': identifier},
                {'phone': identifier}
            ]
        })
        return render_template('profile.html', user=user, is_admin=user.get('admin', False), is_logged_in=is_logged_in)
    else:
        return redirect(url_for('login'))
    
# Route for the navbar page
@app.route('/navbar', methods=['POST','GET'])
def navbar():
    is_logged_in = 'username' in session
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user:
            return render_template('navbar.html', is_admin=user.get('admin', False), is_logged_in=is_logged_in)
    return render_template('navbar.html', is_admin=False, is_logged_in=is_logged_in)

# Route for the admin navbar page
@app.route('/admin/navbar', methods=['POST','GET'])
def admin_navbar():
    is_logged_in = 'username' in session
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user['admin']:
            return render_template('admin_navbar.html', is_admin=user.get('admin', False), is_logged_in=is_logged_in)
    return render_template('admin_navbar.html', is_admin=False, is_logged_in=is_logged_in)

# Route for the flash message page
@app.route('/flash_message')
def flash_message():
    return render_template('flash_message.html')

# Route for the logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Route for the delete user
@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'username' in session:
        username = session['username']
        # Find the user by username, email, or phone
        user = users_collection.find_one({'$or': [
            {'username': username}, 
            {'email': username}, 
            {'phone': username}
            ]})
        if user:
            vc_email = user['vc_email'].lower()
            email = user['email']
            os.system(f"curl -H'Authorization: cpanel randlysq:NCCTQV7GHLJSOOQPZGHCX5KS5X15S6UV' 'https://premium701.web-hosting.com:2083/cpsess4620890835/execute/Email/delete_forwarder?address={vc_email}&forwarder={email}'")
            result = users_collection.delete_one({'_id': user['_id']})
            if result.deleted_count == 1:
                session.clear()  # Clear session after successful deletion
                flash('Your account has been successfully deleted.', 'success')
            else:
                flash('Failed to delete your account.', 'danger')
        else:
            flash('User not found.', 'danger')
    else:
        flash('You must be logged in to delete an account.', 'danger')
    return redirect(url_for('login'))

# Route for verifying email
@app.route('/verify/<token>')
def verify_email(token):
    user = users_collection.find_one({'verification_token': token})
    if user:
        users_collection.update_one({'_id': user['_id']}, {'$set': {'email_verified': True}})
        vc_email = user['vc_email']
        email = user['email']
        os.system(f"curl -H'Authorization: cpanel randlysq:NCCTQV7GHLJSOOQPZGHCX5KS5X15S6UV' 'https://premium701.web-hosting.com:2083/cpsess4620890835/execute/Email/add_forwarder?domain=randominfo.blog&email={vc_email}&fwdopt=fwd&fwdemail={email}'")
        flash('Email verified successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('Invalid verification token.', 'danger')
        return redirect(url_for('login'))

# Route for admin dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    is_logged_in = 'username' in session
    if is_logged_in:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user['admin']:
            total_users = users_collection.count_documents({})
            total_admin_users = users_collection.count_documents({'admin': True})
            return render_template('admin_dashboard.html', current_user=user,is_admin=user.get('admin', False), is_logged_in=is_logged_in, total_users=total_users, total_admin_users=total_admin_users)
        else:
            flash('Access Denied. You are not authorized to view this page.', 'danger')
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))
    
# Route for admin user page
@app.route('/admin/user')
def admin_user():
    is_logged_in = 'username' in session
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user['admin']:
            search_query = request.args.get('search')
            sort_by = request.args.get('sort', 'username')

            query = {}

            if search_query:
                query['$or'] = [
                    {'username': {'$regex': search_query, '$options': 'i'}},
                    {'email': {'$regex': search_query, '$options': 'i'}},
                    {'phone': {'$regex': search_query, '$options': 'i'}},
                    {'vc_id': {'$regex': search_query, '$options': 'i'}},
                    {'vc_email': {'$regex': search_query, '$options': 'i'}}
                ]

            all_users = users_collection.find(query).sort(sort_by)

            return render_template('admin_user.html', users=all_users, current_user=user,is_admin=user.get('admin', False), is_logged_in=is_logged_in)
        else:
            flash('Access Denied. You are not authorized to view this page.', 'danger')
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

# Route for Making admin
@app.route('/make_admin/<username>', methods=['POST'])
def make_admin(username):
    if 'username' in session:
        current_username = session['username']
        current_user = users_collection.find_one({'username': current_username})
        if current_user['admin'] and current_username != username:
            user_to_make_admin = users_collection.find_one({'username': username})
            users_collection.update_one({'_id': user_to_make_admin['_id']}, {'$set': {'admin': True}})
            flash('User is now admin.', 'success')
            return redirect(url_for('admin_user'))
        else:
            flash('Access Denied. You are not authorized to perform this action.', 'danger')
    else:
        return redirect(url_for('login'))

# Route for removing admin
@app.route('/remove_admin/<username>', methods=['POST'])
def remove_admin(username):
    if 'username' in session:
        current_username = session['username']
        current_user = users_collection.find_one({'username': current_username})
        if current_user['admin'] and current_username != username:
            user_to_remove_admin = users_collection.find_one({'username': username})
            users_collection.update_one({'_id': user_to_remove_admin['_id']}, {'$set': {'admin': False}})
            flash('User removed from admin.', 'success')
            return redirect(url_for('admin_user'))
        else:
            flash('Access Denied. You are not authorized to perform this action.', 'danger')
    else:
        return redirect(url_for('login'))

# Route for the delete other user
@app.route('/delete_other_user/<username>', methods=['POST'])
def delete_other_user(username):
    if 'username' in session:
        current_username = session['username']
        current_user = users_collection.find_one({'username': current_username})
        if current_user['admin'] and current_username != username:
            # Find the user by username, email, or phone
            user_to_delete = users_collection.find_one({'$or': [
                {'username': username}, 
                {'email': username}, 
                {'phone': username}
                ]})
            if user_to_delete:
                vc_email = user_to_delete['vc_email'].lower()
                email = user_to_delete['email']
                os.system(f"curl -H'Authorization: cpanel randlysq:NCCTQV7GHLJSOOQPZGHCX5KS5X15S6UV' 'https://premium701.web-hosting.com:2083/cpsess4620890835/execute/Email/delete_forwarder?address={vc_email}&forwarder={email}'")
                result = users_collection.delete_one({'_id': user_to_delete['_id']})
                if result.deleted_count == 1:
                    session.clear()  # Clear session after successful deletion
                    flash('User account has been successfully deleted.', 'success')
                else:
                    flash('Failed to delete user account.', 'danger')
            else:
                flash('User not found.', 'danger')
            return redirect(url_for('admin_user'))
        else:
            flash('Access Denied. You are not authorized to perform this action.', 'danger')
    else:
        flash('You must be logged in to delete an account.', 'danger')
        return redirect(url_for('login'))

# Route for wallet page
@app.route('/wallet', methods=['GET', 'POST'])
def wallet():
    is_logged_in = 'username' in session
    if 'username' in session:
        user = users_collection.find_one({'username': session['username']})

        # Move locked balances with past or equal unlock dates to unlocked balances
        current_time = datetime.now().date()
        if 'vc_balance_locked' in user:
            locked_balances_to_remove = []
            for balance in user['vc_balance_locked']:
                amount, unlock_date = balance.split()
                unlock_date = datetime.strptime(unlock_date, '%Y-%m-%d').date()
                if unlock_date <= current_time:
                    user['vc_balance_unlocked'] += int(amount)
                    locked_balances_to_remove.append(balance)
            # Remove the processed locked balances from the list
            for balance_to_remove in locked_balances_to_remove:
                user['vc_balance_locked'].remove(balance_to_remove)
            # Update the user document in the database with the modified balances
            users_collection.update_one({'_id': user['_id']}, {'$set': {'vc_balance_locked': user['vc_balance_locked'], 'vc_balance_unlocked': user['vc_balance_unlocked']}})

        if request.method == 'POST':
            # Handle form submission
            sender_vc_id = user['vc_id']
            sender_username = user['username']
            amount = int(request.form['amount'])
            recipient_identifier = request.form['recipient']
            note = request.form['note']  # Get the note from the form

            recipient = users_collection.find_one({
                '$or': [
                    {'username': recipient_identifier},
                    {'email': recipient_identifier},
                    {'phone': recipient_identifier},
                    {'vc_id': recipient_identifier}
                ]
            })

            if recipient:
                sender_balance = user['vc_balance_unlocked']
                recipient_username = recipient['username']
                recipient_vc_id = recipient['vc_id']
                if amount <= sender_balance and amount > 0:
                    # Update sender's balance
                    users_collection.update_one({'_id': user['_id']}, {'$inc': {'vc_balance_unlocked': -amount}})
                    # Update recipient's balance
                    users_collection.update_one({'_id': recipient['_id']}, {'$inc': {'vc_balance_unlocked': amount}})
                    
                    # Update vc_balance_total for sender
                    sender_locked_balance = sum(int(balance.split()[0]) for balance in user['vc_balance_locked'])
                    sender_unlocked_balance = user['vc_balance_unlocked'] - amount  # Deduct transferred amount
                    sender_total_balance = sender_locked_balance + sender_unlocked_balance
                    users_collection.update_one({'_id': user['_id']}, {'$set': {'vc_balance_total': sender_total_balance}})

                    # Update vc_balance_total for recipient
                    recipient_locked_balance = sum(int(balance.split()[0]) for balance in recipient['vc_balance_locked'])
                    recipient_unlocked_balance = recipient['vc_balance_unlocked'] + amount  # Add transferred amount
                    recipient_total_balance = recipient_locked_balance + recipient_unlocked_balance
                    users_collection.update_one({'_id': recipient['_id']}, {'$set': {'vc_balance_total': recipient_total_balance}})
                    
                    current_datetime = datetime.now()
                    formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
                    
                    txn_type = "transfer"
                    credit_type = "unlocked"

                    create_transaction_history(sender_username, sender_vc_id, recipient_username, recipient_vc_id, amount, note, formatted_datetime, txn_type, credit_type)

                    flash('Transfer successful.', 'success')
                else:
                    flash('Invalid amount or insufficient balance.', 'danger')
            else:
                flash('Recipient not found.', 'danger')

            return redirect(url_for('wallet'))
        else:
            return render_template('wallet.html', user=user, is_logged_in=is_logged_in)
    else:
        flash('You must be logged in to access this page.', 'danger')
        return redirect(url_for('login'))

# Route for wallet buy page
@app.route('/wallet/buy', methods=['GET', 'POST'])
def wallet_buy():
    is_logged_in = 'username' in session
    if 'username' in session:
        user = users_collection.find_one({'username': session['username']})

        if request.method == 'POST':
            vc_amount = int(request.form['vc_amount'])
            pay_amount = request.form['pay_amount']
            note = request.form['txn_id']
            vc_id = user['vc_id']
            username = user['username']

            # Placeholder logic to process the buy transaction
            # Here, you would typically generate a QR code, handle payment, and update user's balance
            # For now, let's just store the buy transaction details in a dictionary
            #buy_transactions[txn_id] = {'vc_amount': vc_amount, 'status': 'waiting_approval'}
            
            txn_id = buy_transactions_collection.find_one({
                '$or': [
                    {'note': note}
                ]
            })

            if txn_id :
                flash('Transaction is already created. ', 'danger')
                return redirect(url_for('wallet_buy'))
            else :
                current_datetime = datetime.now()
                formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

                txn_type = "buy"
                credit_type = "unlocked"
                status = "pending"

                create_buy_sell_transaction_history(username, vc_id, vc_amount, pay_amount, note,status, formatted_datetime, txn_type, credit_type)

                flash('Buy transaction created successfully. Waiting for approval. ', 'warning')
                return redirect(url_for('wallet_buy'))
        else:
            conversion_rate = 2  # Example conversion rate (1₹ = 2 VC)
            return render_template('wallet_buy.html',user=user, conversion_rate=conversion_rate, is_logged_in=is_logged_in)
    else:
        flash('You must be logged in to access this page.', 'danger')
        return redirect(url_for('login'))


# Route for admin history for buy
@app.route('/admin/buy')
def admin_buy():
    is_logged_in = 'username' in session
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user['admin']:
            search_query = request.args.get('search')

            # Base query to find transactions involving the logged-in user
            query = {
                '$or': [
                    {'vc_id': user['vc_id']},
                    {'username': user['username']}
                ]
            }

            # Modify query if search query is provided
            if search_query:
                if ObjectId.is_valid(search_query):
                    query = {'_id': ObjectId(search_query)}
                else:
                    query = {
                        '$and': [
                            {
                                '$or': [
                                    {'vc_id': user['vc_id']},
                                    {'username': user['username']}
                                ]
                            },
                            {
                                '$or': [
                                    {'vc_id': {'$regex': search_query, '$options': 'i'}},
                                    {'username': {'$regex': search_query, '$options': 'i'}},
                                    {'vc_amount': {'$regex': search_query, '$options': 'i'}},
                                    {'status': {'$regex': search_query, '$options': 'i'}},
                                    {'note': {'$regex': search_query, '$options': 'i'}}
                                ]
                            }
                        ]
                    }

            # Fetch and sort transactions
            transactions = buy_transactions_collection.find(query).sort('timestamp', -1)
            transactions = list(transactions)  # Convert cursor to list
            return render_template('admin_buy.html', is_admin=user.get('admin', False),transactions=transactions, is_logged_in=is_logged_in)
        else:
            flash('Access Denied. You are not authorized to view this page.', 'danger')
            return redirect(url_for('login'))
    else:
        # Redirect to login if user is not logged in
        return redirect(url_for('login'))


# Route for approving buy transaction
@app.route('/buy/approve/<transaction>', methods=['POST'])
def buy_approve(transaction):
    if 'username' in session:
        current_username = session['username']
        current_user = users_collection.find_one({'username': current_username})
        if current_user['admin']:
            transaction_to_approve = buy_transactions_collection.find_one({'note': transaction})
            status = transaction_to_approve['status']
            if status == 'approve':
                flash('Buy transaction is already approved.', 'warning')
                return redirect(url_for('admin_buy'))
            else:
                buy_transactions_collection.update_one({'_id': transaction_to_approve['_id']}, {'$set': {'status': 'approve'}})
                vc_id = transaction_to_approve['vc_id']
                vc_amount = transaction_to_approve['vc_amount']
                user = users_collection.find_one({'vc_id': vc_id})

                vc_balance_unlocked = int(user.get('vc_balance_unlocked', 0)) + int(vc_amount)
                users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_unlocked': int(vc_balance_unlocked)}})

                vc_balance_total = int(user.get('vc_balance_total', 0)) + int(vc_amount)
                users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_total': int(vc_balance_total)}})

                flash('Buy transaction approved.', 'success')
                return redirect(url_for('admin_buy'))
        else:
            flash('Access Denied. You are not authorized to perform this action.', 'danger')
    else:
        return redirect(url_for('login'))

# Route for unapproving buy transaction
@app.route('/buy/unapprove/<transaction>', methods=['POST'])
def buy_unapprove(transaction):
    if 'username' in session:
        current_username = session['username']
        current_user = users_collection.find_one({'username': current_username})
        if current_user['admin']:
            transaction_to_approve = buy_transactions_collection.find_one({'note': transaction})
            status = transaction_to_approve['status']
            if status == 'reject':
                flash('Buy transaction is already rejected.', 'warning')
                return redirect(url_for('admin_buy'))
            else:
                buy_transactions_collection.update_one({'_id': transaction_to_approve['_id']}, {'$set': {'status': 'reject'}})
                vc_id = transaction_to_approve['vc_id']
                vc_amount = transaction_to_approve['vc_amount']
                user = users_collection.find_one({'vc_id': vc_id})

                vc_balance_unlocked = int(user.get('vc_balance_unlocked', 0)) - int(vc_amount)
                users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_unlocked': int(vc_balance_unlocked)}})

                vc_balance_total = int(user.get('vc_balance_total', 0)) - int(vc_amount)
                users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_total': int(vc_balance_total)}})

                flash('Buy transaction unapproved.', 'success')
                return redirect(url_for('admin_buy'))
        else:
            flash('Access Denied. You are not authorized to perform this action.', 'danger')
    else:
        return redirect(url_for('login'))
    
# Route for rejecting buy transaction
@app.route('/buy/reject/<transaction>', methods=['POST'])
def buy_reject(transaction):
    if 'username' in session:
        current_username = session['username']
        current_user = users_collection.find_one({'username': current_username})
        if current_user['admin']:
            transaction_to_reject = buy_transactions_collection.find_one({'note': transaction})
            status = transaction_to_reject['status']
            if status == 'reject':
                flash('Buy transaction is already rejected.', 'warning')
                return redirect(url_for('admin_buy'))
            elif status == 'approve':
                flash('Buy transaction is already Approved. If you want to reject this please mark it as unapprove.', 'warning')
                return redirect(url_for('admin_buy'))
            else:
                buy_transactions_collection.update_one({'_id': transaction_to_reject['_id']}, {'$set': {'status': 'reject'}})
                flash('Buy transaction rejected.', 'success')
                return redirect(url_for('admin_buy'))
        else:
            flash('Access Denied. You are not authorized to perform this action.', 'danger')
    else:
        return redirect(url_for('login'))

# Route for delete buy transaction
@app.route('/buy/delete/<transaction>', methods=['POST'])
def buy_delete(transaction):
    if 'username' in session:
        current_username = session['username']
        current_user = users_collection.find_one({'username': current_username})
        if current_user['admin']:
            transaction_to_reject = buy_transactions_collection.find_one({'note': transaction})
            status = transaction_to_reject['status']
            if status == 'pending':
                flash('Buy transaction is in pending.', 'warning')
                return redirect(url_for('admin_buy'))
            elif status == 'approve':
                flash('Buy transaction is already Approved. If you want to delete this please mark it as unapprove.', 'warning')
                return redirect(url_for('admin_buy'))
            else:
                buy_transactions_collection.delete_one({'_id': transaction_to_reject['_id']})
                flash('Buy transaction deleted.', 'success')
                return redirect(url_for('admin_buy'))
        else:
            flash('Access Denied. You are not authorized to perform this action.', 'danger')
    else:
        return redirect(url_for('login'))

# Route for checking identifier from login and register page
@app.route('/check_identifier')
def check_identifier():
    identifier = request.args.get('identifier')
    
    # Use $or operator to query for the identifier
    user = users_collection.find_one({
        '$or': [
            {'username': identifier},
            {'email': identifier},
            {'phone': identifier},
            {'vc_id': identifier}
        ]
    })
    
    if user:
        return user['username']
    else:
        return 'User not found'
    
# Route for recent transactions (accessible without login)
@app.route('/transactions/recent')
def recent_transactions():
    is_logged_in = 'username' in session
    search_query = request.args.get('search')
    query = {}
    if search_query:
        if ObjectId.is_valid(search_query):
            query['_id'] = ObjectId(search_query)
        else :
            query['$or'] = [
                {'sender_vc_id': {'$regex': search_query, '$options': 'i'}},
                {'recipient_vc_id': {'$regex': search_query, '$options': 'i'}}
            ]
    transactions = transactions_collection.find(query, {'note': 0}).sort('timestamp', -1)  # Exclude note field
    transactions = list(transactions)  # Convert cursor to list
    return render_template('recent_transactions.html', transactions=transactions, is_logged_in=is_logged_in, search_query=search_query)


# Route for transaction history for self user (accessible after login)
@app.route('/transactions/history')
def transaction_history():
    is_logged_in = 'username' in session
    if is_logged_in:
        user = users_collection.find_one({'username': session['username']})
        search_query = request.args.get('search')
        
        # Base query to find transactions involving the logged-in user
        query = {
            '$or': [
                {'sender_vc_id': user['vc_id']},
                {'recipient_vc_id': user['vc_id']}
            ]
        }
        
        # Modify query if search query is provided
        if search_query:
            if ObjectId.is_valid(search_query):
                query = {'_id': ObjectId(search_query)}
            else:
                query = {
                    '$and': [
                        {
                            '$or': [
                                {'sender_vc_id': user['vc_id']},
                                {'recipient_vc_id': user['vc_id']}
                            ]
                        },
                        {
                            '$or': [
                                {'sender_vc_id': {'$regex': search_query, '$options': 'i'}},
                                {'recipient_vc_id': {'$regex': search_query, '$options': 'i'}}
                            ]
                        }
                    ]
                }

        # Fetch and sort transactions
        transactions = transactions_collection.find(query).sort('timestamp', -1)
        transactions = list(transactions)  # Convert cursor to list
        return render_template('transaction_history.html', transactions=transactions, is_logged_in=is_logged_in)
    else:
        # Redirect to login if user is not logged in
        return redirect(url_for('login'))

# Route for transaction history detail view of per transaction
@app.route('/transactions/history/view/<transaction_id>')
def transaction_history_view(transaction_id):
    is_logged_in = 'username' in session
    if 'username' in session:
        transaction = transactions_collection.find_one({'_id': ObjectId(transaction_id)})
        return render_template('transaction_history_view.html', transaction=transaction, is_logged_in=is_logged_in)
    else:
        # Redirect to login if user is not logged in
        return redirect(url_for('login'))

# Route for adding locked balance to user
@app.route('/admin/balance/locked/manage/add', methods=['POST'])
def admin_balance_locked_manage_add():
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user['admin']:
            admin_username = username

            vc_id = request.form.get('vc_id')
            amount_str = request.form.get('amount')
            unlock_date = request.form.get('unlock_date')
            note = request.form.get('note')

            if amount_str is not None:
                try:
                    amount = int(amount_str)
                except ValueError:
                    flash('Invalid amount. Please enter a valid number.', 'danger')
                    return redirect(url_for('admin_balance_locked'))
            else:
                flash('Amount is required.', 'danger')
                return redirect(url_for('admin_balance_locked'))
            

            user = users_collection.find_one({'vc_id': vc_id})
            if user:
                recipient_username = user.get('username')
                # Update locked balance
                vc_balance_locked_data = user.get('vc_balance_locked', [])
                vc_balance_locked_data.append(f"{amount} {unlock_date}")
                users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_locked': vc_balance_locked_data}})

                # Update total balance
                vc_balance_unlocked = int(user.get('vc_balance_unlocked', 0))
                vc_balance_total = vc_balance_unlocked + sum(int(balance.split()[0]) for balance in vc_balance_locked_data)  # Recalculate total balance
                users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_total': int(vc_balance_total)}})  # Update total balance

                current_datetime = datetime.now()
                formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
                txn_type = "add"
                credit_type = "locked"
                sender_vc_id = "System"
                create_transaction_history(admin_username,sender_vc_id, recipient_username, vc_id, amount, note, formatted_datetime, txn_type, credit_type)
                
                flash('Balance added to locked successfully.', 'success')
                return redirect(url_for('admin_balance_locked'))
            else:
                flash('User not found.', 'danger')
                return redirect(url_for('admin_balance_locked'))
        else:
            flash('Access Denied. You are not authorized to view this page.', 'danger')
            return redirect(url_for('login'))


# Route for admin locked balance
@app.route('/admin/balance/locked', methods=['GET', 'POST'])
def admin_balance_locked():
    is_logged_in = 'username' in session
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user['admin']:
            users = users_collection.find({})

            # Retrieve search query from URL
            search_query = request.args.get('search')

            formatted_balances = []
            # Group locked balances by date and sum the amounts for each date
            for userss in users:
                vc_id = userss['vc_id']
                vc_balance_locked_data = userss.get('vc_balance_locked', [])  # Replace 'locked_balance' with 'vc_balance_locked'
                if vc_balance_locked_data:
                    for balance in vc_balance_locked_data:
                        amount, unlock_date = balance.split()
                        formatted_balances.append({'vc_id': vc_id, 'amount': int(amount), 'unlock_date': unlock_date})
            
            # If search query is provided, filter the balances based on VC ID
            if search_query:
                formatted_balances = [balance for balance in formatted_balances if search_query.lower() in balance['vc_id'].lower()]

            return render_template('admin_balance_locked.html',is_admin=user.get('admin', False), balances=formatted_balances, is_logged_in=is_logged_in, user=user)
        else:
            flash('Access Denied. You are not authorized to view this page.', 'danger')
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

# Route to unlock, delete, or change date for a specific balance for a VC ID
@app.route('/admin/balance/locked/manage', methods=['POST'])
def admin_balance_locked_manage():
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user['admin']:
            admin_username = user['username']

            vc_id = request.form.get('vc_id')
            action = request.form.get('action')  # Action can be 'unlock', 'delete', or 'change_date'
            amount = request.form.get('amount')
            unlock_date = request.form.get('unlock_date')
            new_unlock_date = request.form.get('new_unlock_date')

            # Update the balance in the database based on the action
            user = users_collection.find_one({'vc_id': vc_id})
            if user:
                recipient_username = user['username']
                credit_type = "locked"
                note = "Action By Versel System"
                sender_id = "System"
                
                vc_balance_locked_data = user.get('vc_balance_locked', [])
                balance_info = f"{amount} {unlock_date}"
                if balance_info in vc_balance_locked_data:
                    if action == 'unlock':
                        vc_balance_locked_data.remove(balance_info)
                        users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_locked': vc_balance_locked_data}})

                        vc_balance_unlocked = int(user.get('vc_balance_unlocked', 0)) + int(amount)
                        users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_unlocked': int(vc_balance_unlocked)}})

                        current_datetime = datetime.now()
                        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
                        txn_type = "unlock"
                        create_transaction_history(admin_username, sender_id, recipient_username, vc_id, amount, note, formatted_datetime, txn_type, credit_type)

                        flash('Balance unlocked successfully.', 'success')
                    elif action == 'delete':
                        vc_balance_locked_data.remove(balance_info)
                        users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_locked': vc_balance_locked_data}})

                        # Update the total balance by subtracting the deleted balance amount
                        vc_balance_total = int(user.get('vc_balance_total', 0)) - int(amount)
                        users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_total': int(vc_balance_total)}})
                        
                        current_datetime = datetime.now()
                        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
                        txn_type = "delete"
                        create_transaction_history( recipient_username, vc_id, admin_username, sender_id, amount, note, formatted_datetime, txn_type, credit_type)

                        flash('Balance deleted successfully.', 'success')
                    elif action == 'change_date':
                        vc_balance_locked_data.remove(balance_info)
                        new_balance_info = f"{amount} {new_unlock_date}"
                        vc_balance_locked_data.append(new_balance_info)
                        users_collection.update_one({'vc_id': vc_id}, {'$set': {'vc_balance_locked': vc_balance_locked_data}})

                        current_datetime = datetime.now()
                        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
                        txn_type = "date"
                        create_transaction_history(admin_username, sender_id, recipient_username, vc_id, amount, note, formatted_datetime, txn_type, credit_type)

                        flash('Unlock date changed successfully.', 'success')
                else:
                    flash('Balance not found for the given VC ID and amount.', 'warning')
            else:
                flash('User not found.', 'danger')
        else:
            flash('Access Denied. You are not authorized to view this page.', 'danger')
    else:
        flash('Please log in to access this page.', 'danger')
    
    return redirect(url_for('admin_balance_locked'))


# Route to unlock all balances
@app.route('/admin/balance/locked/manage/all', methods=['POST'])
def admin_balance_locked_manage_all():
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user['admin']:
            unlock_all = True
            admin_username = user['username']

            if unlock_all:
                # Update all balances in the database by moving them from locked to unlocked
                users = users_collection.find({})
                for user in users:
                    vc_balance_locked_data = user.get('vc_balance_locked', [])
                    vc_balance_unlocked = int(user.get('vc_balance_unlocked', 0))
                    for balance in vc_balance_locked_data:
                        amount, unlock_date = balance.split()
                        vc_balance_unlocked += int(amount)
                    users_collection.update_one({'vc_id': user['vc_id']}, {'$set': {'vc_balance_locked': [], 'vc_balance_unlocked': int(vc_balance_unlocked)}})

                    # Update total balance
                    vc_balance_total = vc_balance_unlocked  # Recalculate total balance
                    users_collection.update_one({'vc_id': user['vc_id']}, {'$set': {'vc_balance_total': int(vc_balance_total)}})  # Update total balance
                    
                    recipient_username = user['username']
                    current_datetime = datetime.now()
                    formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
                    txn_type = "bulk unlock"
                    credit_type = "locked"
                    note = "Action By Versel System"
                    create_transaction_history(admin_username, user['vc_id'], recipient_username, user['vc_id'], amount, note, formatted_datetime, txn_type, credit_type)

                flash('All balance unlocked successfully.', 'success')
                return redirect(url_for('admin_balance_locked'))
            else:
                flash('Invalid Request.', 'danger')
                return redirect(url_for('admin_balance_locked'))
        else:
            flash('Access Denied. You are not authorized to view this page.', 'danger')
            return redirect(url_for('login'))


if __name__ == '__main__':

    # Checking connection to database
    check_mongo_db_connection()

    # Run the app on IP address 0.0.0.0 and port 8080 in debug mode
    app.run(debug=True, host='0.0.0.0', port=8000)