from flask import Flask, render_template, request, redirect, url_for, session, flash
import bcrypt
import random
import string
import base64
from pymongo import MongoClient
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = "e06ad29d3a8de30f758e5ec0dbdaab970db52def93177b23953f77c984900858"

client = MongoClient('mongodb://localhost:27017/')
db = client['Blogger']
collection = db['Users']

# Function to generate a random OTP
def generate_otp():
    digits = string.digits
    return ''.join(random.choice(digits) for i in range(6))

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        plain_password = request.form['password']

        # Retrieve user data from MongoDB based on the entered email
        user_data = collection.find_one({"email": email})

        if user_data and bcrypt.checkpw(plain_password.encode('utf-8'), user_data['password'].encode('utf-8')):
            session['user_id'] = str(user_data['_id'])  # Store user ID in session for OTP verification
            flash("Login successful! Welcome, " + user_data['name'] + "!", "success")
            return redirect(url_for('profile'))
        else:
            return "Invalid email or password. Please try again."

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        plain_password = request.form['password']
        email = request.form['email']

        # Check if the email already exists in the database
        existing_user = collection.find_one({"email": email})
        if existing_user:
            return "An account with this email already exists. Please login or use a different email."

        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create a document to insert into the MongoDB collection
        data = {"name": name, "password": hashed_password, "email": email}

        try:
            # Insert the document into the MongoDB collection
            collection.insert_one(data)
            return redirect(url_for('login'))  # Redirect to the login page after successful signup
        except Exception as e:
            return f"Failed to create an account: {str(e)}", 500

    return render_template('signup.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # Check if the provided email or phone number exists in the database
        user_data = collection.find_one({"$or": [{"email": email}]})

        if user_data:
            otp = generate_otp()

            # Here, you can implement the logic to send the OTP to the user's registered email or phone number.
            # For the sake of this example, let's just print the OTP.
            print("OTP:", otp)

            session['otp'] = otp  # Store OTP in session for verification
            session['user_id'] = str(user_data['_id'])  # Store user ID in session for OTP verification
            return redirect(url_for('verify_otp'))
        else:
            return "Email or phone number not found. Please check and try again."

    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user_id' not in session or 'otp' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        otp = session['otp']
        entered_otp = request.form['otp']

        if entered_otp == otp:
            # OTP verification successful. Implement your logic to reset the password here.
            # For this example, let's just redirect to the login page.
            session.pop('otp', None)  # Clear the OTP from the session
            return redirect(url_for('login'))
        else:
            return "Invalid OTP. Please try again."

    return render_template('verify_otp.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_data = collection.find_one({"_id": ObjectId(user_id)})

    if user_data:
        if request.method == 'POST':
            # Get the additional profile information from the form
            name = request.form['name']
            bio = request.form['bio']
            social_media_links = request.form['social_media_links']
            # Handling profile picture upload
            profile_pic = request.files['profile_pic']
            profile_pic_b64 = None  # Initialize profile_pic_b64 as None

            if profile_pic:
                image_binary = profile_pic.read()
                profile_pic_b64 = base64.b64encode(image_binary).decode('utf-8')

            # Update the user's profile information in the Users collection
            collection.update_one({"_id": ObjectId(user_id)}, {
                "$set": {
                    "name": name,
                    "bio": bio,
                    "social_media_links": social_media_links,
                    "profile_pic": profile_pic_b64  # Assign profile_pic_b64 directly
                }
            })

            flash("Profile updated successfully!", "success")
            return redirect(url_for('profile'))

        return render_template('profile.html', user_data=user_data)
    else:
        return "User not found."

if __name__ == '__main__':
    app.run(debug=True, port=8000)