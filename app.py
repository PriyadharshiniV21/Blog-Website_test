from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from bs4 import BeautifulSoup
import bcrypt
import random
import string
import base64
from pymongo import MongoClient
from bson.objectid import ObjectId
from collections import deque

app = Flask(__name__)
app.secret_key = "e06ad29d3a8de30f758e5ec0dbdaab970db52def93177b23953f77c984900858"

client = MongoClient('mongodb://localhost:27017/')
db = client['Blogger']
users = db['Users']
blogs = db['Blogs']
media = db['Media']

# Function to generate a random OTP
def generate_otp():
    digits = string.digits
    return ''.join(random.choice(digits) for i in range(6))

# Fetch existing blogs from the Blogs collection and store them in a deque
blogs_list = deque(db['Blogs'].find({}))
# Reverse the order of the deque to show new blogs first and old blogs last
blogs_list.reverse()

@app.route('/')
def index():
    return render_template('index.html', logged_in=False, blogs=blogs_list)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        plain_password = request.form['password']

        # Retrieve user data from MongoDB based on the entered email
        user_data = users.find_one({"email": email})

        if user_data and bcrypt.checkpw(plain_password.encode('utf-8'), user_data['password'].encode('utf-8')):
            session['user_id'] = str(user_data['_id'])  # Store user ID in session for OTP verification
            session['logged_in'] = True
            return render_template('index.html', logged_in=True, blogs=blogs_list)
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
        existing_user = users.find_one({"email": email})
        if existing_user:
            return "An account with this email already exists. Please login or use a different email."

        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create a document to insert into the MongoDB collection
        data = {"name": name, "password": hashed_password, "email": email}

        try:
            # Insert the document into the MongoDB collection
            users.insert_one(data)
            return redirect(url_for('login'))  # Redirect to the login page after successful signup
        except Exception as e:
            return f"Failed to create an account: {str(e)}", 500

    return render_template('signup.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # Check if the provided email or phone number exists in the database
        user_data = users.find_one({"$or": [{"email": email}]})

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
    user_data = users.find_one({"_id": ObjectId(user_id)})
    
    blog_data = []
    if 'blogs' in user_data:
        for blog_id in user_data['blogs']:
            blog = blogs.find_one({"_id": ObjectId(blog_id)})
            blog_data.append(blog)
            
    if user_data:
        if request.method == 'POST':
            # Get the additional profile information from the form
            name = request.form['name']
            bio = request.form['bio']
            linkedin = request.form['linkedin']
            github = request.form['github']
            discord = request.form['discord']
            youtube = request.form['youtube']
            instagram = request.form['instagram']

            # Handling profile picture upload
            profile_pic = request.files['profile_pic']
            profile_pic_b64 = user_data.get('profile_pic')  # Retrieve the existing profile picture (if any)

            if profile_pic:
                image_binary = profile_pic.read()
                profile_pic_b64 = base64.b64encode(image_binary).decode('utf-8')

            # Update the user's profile information in the Users collection
            users.update_one({"_id": ObjectId(user_id)}, {
                "$set": {
                    "name": name,
                    "bio": bio,
                    "linkedin": linkedin,
                    "github": github,
                    "discord": discord,
                    "youtube": youtube,
                    "instagram": instagram,
                    "profile_pic": profile_pic_b64,  # Assign profile_pic_b64 directly
                }
            })

            flash("Profile updated successfully!", "success")
            return redirect(url_for('profile'))

        return render_template('profile.html', user_data=user_data, blog_data=blog_data)
    else:
        return "User not found."
    
@app.route('/update_password', methods=['POST'])
def update_password():
    if 'user_id' not in session:
        return jsonify({"message": "User not authenticated."}), 401

    user_id = session['user_id']
    user_data = users.find_one({"_id": ObjectId(user_id)})

    if user_data:
        if request.method == 'POST':
            new_password = request.json.get('password')
            if new_password:
                # Implement secure password hashing before storing in the database
                # For example, you can use bcrypt or passlib to hash the password
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

                users.update_one({"_id": ObjectId(user_id)}, {
                    "$set": {
                        "password": hashed_password
                    }
                })

                return jsonify({"message": "Password updated successfully."}), 200
            else:
                return jsonify({"message": "Invalid request. New password not provided."}), 400
    else:
        return jsonify({"message": "User not found."}), 404
    
@app.route('/create_blog', methods=['GET', 'POST'])
def create_blog():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        user_data = users.find_one({"_id": ObjectId(user_id)})

        if user_data:
            # Get the blog title and description from the form
            title = request.form['title']
            description = request.form['description']
            blog_text = request.form['blog_text']
            image_data = request.form['image_data']
            video_data = request.form['video_data']
            document_data = request.form['document_data']
            link_data = request.form['link_data']

            # Create a new blog entry and store it in the Blogs collection
            blog_entry = {
                "user_id": user_id,
                "title": title,
                "description": description,
                "blog_text": blog_text
            }
            
            # Get the inserted blog_id
            blog_id = blogs.insert_one(blog_entry).inserted_id  

            media_entry = {
                    "blog_id": blog_id,  # Link the media to the specific blog
                    "image_data": image_data,
                    "video_data": video_data,
                    "document_data": document_data,
                    "link_data": link_data
                }
            
            media.insert_one(media_entry)

            # Add the blog_id to the user's 'blogs' field in the User collection
            users.update_one(
                {"_id": ObjectId(user_id)},
                {"$push": {"blogs": blog_id}}
            )
            
            flash("Blog article created successfully!", "success")
            return redirect(url_for('create_blog'))

    return render_template('create_blog.html')

@app.route('/blog/<blog_id>', methods=['GET', 'POST'])
def blog_article(blog_id):
    # Fetch the blog from the Blogs collection based on the provided blog_id
    blog = blogs.find_one({"_id": ObjectId(blog_id)})

    if blog:
        logged_in = session.get('logged_in', False)
        if request.method == 'POST':
            if logged_in:
                # Handle like button click
                if 'like_btn' in request.form:
                    # Increment the likes count and update it in the database
                    blogs.update_one({"_id": ObjectId(blog_id)}, {"$inc": {"likes": 1}})
                    blog = blogs.find_one({"_id": ObjectId(blog_id)})  # Fetch the updated blog document
                    return jsonify({"likes": blog['likes']})

                # Handle comment button click
                elif 'comment_btn' in request.form:
                    comment_text = request.form['comment']
                    if comment_text:
                        # Append the new comment to the comments list and update it in the database
                        blogs.update_one({"_id": ObjectId(blog_id)}, {"$push": {"comments": comment_text}})
                        blog = blogs.find_one({"_id": ObjectId(blog_id)})  # Fetch the updated blog document
                        return jsonify({"comments": blog['comments']})

                # Handle bookmark button click
                elif 'bookmark_btn' in request.form:
                    # Increment the bookmarks count and update it in the database
                    blogs.update_one({"_id": ObjectId(blog_id)}, {"$inc": {"bookmarks": 1}})
                    blog = blogs.find_one({"_id": ObjectId(blog_id)})  # Fetch the updated blog document
                    return jsonify({"bookmarks": blog['bookmarks']})
                
            return jsonify({"message": "Please log in to perform this action."}), 401

        return render_template('blog_article.html', blog=blog, logged_in=logged_in, logged_user=False)
    else:
        return "Blog not found."
    
@app.route('/profile/blog/<blog_id>', methods=['GET', 'POST'])
def remove_blog(blog_id):
    user_id = session['user_id']
    blog = blogs.find_one({"_id": ObjectId(blog_id)})

    if blog:
        if request.method == 'POST':
            if 'remove_btn' in request.form:
                blogs.delete_one({"_id": ObjectId(blog_id)})
                users.update_one(
                        {"_id": ObjectId(user_id)},
                        {"$pull": {"blogs": blog_id}}
                    )
                flash("Blog removed successfully!", "success")
                return redirect(url_for('index'))
            
        return render_template('blog_article.html', blog=blog, logged_user=True)
    else:
        return "Blog not found."
    
@app.route('/logout')
def logout():
    # Clear user-related session variables upon logout
    session.pop('user_id', None)
    session['logged_in'] = False
    return redirect(url_for('login'))
    
if __name__ == '__main__':
    app.run(debug=True, port=8000)