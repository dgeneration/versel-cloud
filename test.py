from flask import Flask, render_template, request, redirect, session , jsonify
from pymongo import MongoClient
import bcrypt
import random
import string
import base64

app = Flask(__name__)
app.secret_key = "secret_key"

def check_mongodb_connection():
    try:
        client = MongoClient('mongodb+srv://app:JAY252006@versel-cloud.a5krarz.mongodb.net/')
        client.server_info()  # Attempt to retrieve server information
        return True
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}")
        return False

def generate_credit_id():
    prefix = "0xVC"
    credit_length = 30 - len(prefix)  # Adjust the length considering the prefix
    characters = string.ascii_letters + string.digits
    return prefix + ''.join(random.choices(characters, k=credit_length))

# Function to encrypt balance
def encrypt_balance(balance):
    return base64.b64encode(balance.encode('utf-8')).decode('utf-8')

# Function to decrypt balance
def decrypt_balance(encrypted_balance):
    return base64.b64decode(encrypted_balance).decode('utf-8')

if check_mongodb_connection():
    client = MongoClient('mongodb+srv://app:JAY252006@versel-cloud.a5krarz.mongodb.net/')
    db = client['versel-cloud']
    users_collection = db['user']
    versel_credit_collection = db['versel_credit']  # Initialize versel_credit collection
    print("Connected to MongoDB.")
else:
    print("Failed to connect to MongoDB. Please check your connection settings.")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect('/dashboard')
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        country_code = request.form['country_code']
        mobile = request.form['mobile']
        password = request.form['password']

        if users_collection.find_one({'$or': [{'email': email}, {'mobile': mobile}]}):
            return "Email or mobile number already exists. Please use a different one."
        
        mobile_with_country_code = country_code + mobile
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        encrypted_balance = encrypt_balance('0.00')  # Encrypting default balance
        
        # Generate or retrieve the user's credit ID
        existing_user = users_collection.find_one({}, {'credit_id': 1})
        if existing_user:
            credit_id = existing_user['credit_id']
        else:
            credit_id = generate_credit_id()

        users_collection.insert_one({
            'username': username,
            'email': email,
            'country_code': country_code,
            'mobile': mobile,
            'mobile_with_country_code': mobile_with_country_code,
            'credit_id': credit_id,  # Use the generated/retrieved credit ID
            'password': hashed_password,
            'balance': encrypted_balance,  # Adding encrypted balance
            'admin': False  # Initializing admin status as False
        })

        # Check if the credit ID exists in the versel_credit collection
        existing_credit_id = versel_credit_collection.find_one({'credit_id': credit_id})
        if not existing_credit_id:
            versel_credit_collection.insert_one({
                'credit_id': credit_id,
                'balance': encrypted_balance
            })

        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect('/dashboard')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        user = users_collection.find_one({'username': username})
        if user and bcrypt.checkpw(password, user['password']):
            session['username'] = username
            return redirect('/dashboard')
        else:
            return "Invalid username/password combination"
    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})

        # Decrypting balance for display
        decrypted_balance = decrypt_balance(user['balance'])
        user['balance'] = "{:.2f}".format(float(decrypted_balance))  # Formatting to two decimal places

        return render_template('profile.html', user=user)
    return redirect('/login')

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'username' in session:
        username = session['username']
        users_collection.delete_one({'username': username})
        session.pop('username', None)
        return redirect('/')
    else:
        return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        return render_template('dashboard.html', current_user=user)
    else:
        return redirect('/login')

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'username' not in session:
        return redirect('/login')

    if request.method == 'POST':
        sender_username = session['username']
        sender = users_collection.find_one({'username': sender_username})

        recipient_identifier = request.form['recipient']
        amount_str = request.form['amount']

        # Validate amount
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be a positive number.")
        except ValueError:
            return "Invalid transfer amount. Please enter a valid number."

        # Search for the recipient based on mobile, username, or Versel credit ID
        recipient = None
        if recipient_identifier.isdigit():  # If input is a mobile number
            recipient = users_collection.find_one({'mobile': recipient_identifier})
        else:  # Otherwise, search by username or Versel credit ID
            recipient = users_collection.find_one({'$or': [{'username': recipient_identifier}, {'credit_id': recipient_identifier}]})

        if recipient:
            recipient_name = recipient['username']
            recipient_balance_str = recipient['balance']
            recipient_balance = float(decrypt_balance(recipient_balance_str))

            sender_balance_str = sender['balance']
            sender_balance = float(decrypt_balance(sender_balance_str))

            if recipient_name != sender_username:  # Ensure sender is not the recipient
                if sender_balance >= amount:
                    # Deduct from sender and add to recipient
                    sender_balance -= amount
                    recipient_balance += amount

                    # Update sender's balance
                    encrypted_sender_balance = encrypt_balance(str(sender_balance))
                    users_collection.update_one({'username': sender_username}, {'$set': {'balance': encrypted_sender_balance}})

                    # Update recipient's balance
                    encrypted_recipient_balance = encrypt_balance(str(recipient_balance))
                    users_collection.update_one({'username': recipient_name}, {'$set': {'balance': encrypted_recipient_balance}})
                    
                    # Update balances in versel_credit_collection as well
                    versel_credit_collection.update_one({'credit_id': sender_username}, {'$set': {'balance': encrypted_sender_balance}})
                    versel_credit_collection.update_one({'credit_id': recipient['credit_id']}, {'$set': {'balance': encrypted_recipient_balance}})

                    return f"Successfully transferred {amount} Versel credits to {recipient_name}."
                else:
                    return "Insufficient balance for transfer."
            else:
                return "You cannot transfer credits to your own account."
        else:
            return "Recipient not found. Please check the entered mobile number, username, or Versel credit ID."

    return render_template('transfer.html')

@app.route('/get_recipient_name', methods=['POST'])
def get_recipient_name():
    identifier = request.json.get('identifier')
    recipient = None
    if identifier.isdigit():  # If input is a mobile number
        recipient = users_collection.find_one({'mobile': identifier})
    else:  # Otherwise, search by username or Versel credit ID
        recipient = users_collection.find_one({'$or': [{'username': identifier}, {'credit_id': identifier}]})

    if recipient:
        return jsonify({'success': True, 'name': recipient['username']})
    else:
        return jsonify({'success': False})
    
@app.route('/admin_dashboard')
def admin_dashboard():
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
                    {'mobile': {'$regex': search_query, '$options': 'i'}},
                    {'credit_id': {'$regex': search_query, '$options': 'i'}}
                ]

            all_users = users_collection.find(query).sort(sort_by)

            return render_template('admin_dashboard.html', users=all_users, current_user=user, decrypt_balance=decrypt_balance)
        else:
            return "Access Denied. You are not authorized to view this page."
    else:
        return redirect('/login')

@app.route('/make_admin/<username>', methods=['POST'])
def make_admin(username):
    if 'username' in session:
        current_username = session['username']
        current_user = users_collection.find_one({'username': current_username})
        if current_user['admin'] and current_username != username:
            user_to_make_admin = users_collection.find_one({'username': username})
            users_collection.update_one({'_id': user_to_make_admin['_id']}, {'$set': {'admin': True}})
            return redirect('/admin_dashboard')
        else:
            return "Access Denied. You are not authorized to perform this action."
    else:
        return redirect('/login')

@app.route('/update_balance', methods=['POST'])
def update_balance():
    if 'username' in session:
        current_user = users_collection.find_one({'username': session['username']})
        if current_user['admin']:
            username = request.form['username']
            new_balance = request.form['new_balance']

            # Encrypting the new balance
            encrypted_balance = encrypt_balance(new_balance)

            users_collection.update_one({'username': username}, {'$set': {'balance': encrypted_balance}})
            # Also update the balance in versel_credit collection
            versel_credit_collection.update_one({'credit_id': username}, {'$set': {'balance': encrypted_balance}})
            return redirect('/admin_dashboard')
        else:
            return "Access Denied. You are not authorized to perform this action."
    else:
        return redirect('/login')
    
@app.route('/remove_admin/<username>', methods=['POST'])
def remove_admin(username):
    if 'username' in session:
        current_username = session['username']
        current_user = users_collection.find_one({'username': current_username})
        if current_user['admin'] and current_username != username:
            user_to_remove_admin = users_collection.find_one({'username': username})
            users_collection.update_one({'_id': user_to_remove_admin['_id']}, {'$set': {'admin': False}})
            return redirect('/admin_dashboard')
        else:
            return "Access Denied. You are not authorized to perform this action."
    else:
        return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)