from flask import Flask, render_template, request, redirect, flash, url_for, session
from datetime import datetime, timedelta
from argon2 import PasswordHasher
from config import Config
from models import db, User
from flask_mail import Mail, Message
import random
import string
import re
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

REHASH_PERIOD = timedelta(days=30)  # Rehash if inactive for 30 days
ph = PasswordHasher()

# Initialize the mail extension
mail = Mail(app)

# Secret key for Flask sessions
app.secret_key = 'your_secret_key'  # Replace with a secure key

# Password strength validation
def validate_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password))

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/account_home')
def account_home():
    user_id = session.get('user_id')  # Get the user_id from the session

    # Check if user_id is available
    if user_id:
        # Fetch the user from the database using the user_id
        user = User.query.get(user_id)
        
        if user:
            return render_template('account_home.html', user=user)  # Pass the user object to the template
        else:
            flash("User not found")
            return redirect(url_for('login'))
    else:
        flash("You need to log in first")
        return redirect(url_for('login'))  # Redirect to login if user is not logged in



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if not validate_password(password):
            flash("Password must contain at least one uppercase letter, one number, and one special character.")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Email already exists")
            return redirect(url_for('register'))

        password_hash = ph.hash(password)
        new_user = User(username=username, password_hash=password_hash, last_login=datetime.utcnow(), email=email)
        db.session.add(new_user)
        db.session.commit()

        # Log the user in by setting the session user_id
        session['user_id'] = new_user.id  # Log the user in immediately after registration

        flash("User registered successfully")
        return redirect(url_for('account_home'))  # Redirect to the account home page after registration

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user:
            if user.failed_attempts >= 3:
                flash('Your account is locked. Please unlock it using OTP.')
                return redirect(url_for('unlock_account'))

            try:
                if ph.verify(user.password_hash, password):
                    new_password_hash = ph.hash(password)
                    user.password_hash = new_password_hash

                    # Check if rehash is needed
                    rehash_due_to_time = datetime.utcnow() - user.last_login > REHASH_PERIOD
                    if rehash_due_to_time or ph.check_needs_rehash(user.password_hash):
                        user.password_hash = ph.hash(password)
                        flash("Password rehashed for security.")

                    user.last_login = datetime.utcnow()
                    user.failed_attempts = 0
                    db.session.commit()
                    session['user_id'] = user.id 
                    flash("Login successful")
                    return redirect(url_for('account_home'))
            except VerifyMismatchError:
                user.failed_attempts += 1
                db.session.commit()
                remaining_attempts = 3 - user.failed_attempts
                flash(f"Incorrect password. You have {remaining_attempts} attempt{'s' if remaining_attempts > 1 else ''} left.")
                if user.failed_attempts >= 3:
                    flash("Your account has been locked due to multiple failed login attempts.")
                return redirect(url_for('login'))

        flash("Invalid username or password")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if request.method == 'POST':
        username = request.form['username']
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        user = User.query.filter_by(username=username).first()

        if user and ph.verify(user.password_hash, old_password):
            if not validate_password(new_password):
                flash("New password must contain at least one uppercase letter, one number, and one special character.")
                return redirect(url_for('update_password'))

            user.password_hash = ph.hash(new_password)
            db.session.commit()
            flash("Password updated successfully")
            return redirect(url_for('login'))

        flash("Invalid credentials")
        return redirect(url_for('update_password'))

    return render_template('update_password.html')

# OTP generation function
def generate_otp(length=6):
    """Generate a random OTP consisting of digits."""
    otp = ''.join(random.choice(string.digits) for _ in range(length))
    return otp

@app.route('/unlock_account', methods=['GET', 'POST'])
def unlock_account():
    if request.method == 'POST':
        email = request.form['email']
        otp = generate_otp()  # Generate the OTP

        # Save OTP to session for later verification
        session['otp'] = otp
        session['email'] = email
        # Create the email message
        msg = Message("Your OTP Code",
                      recipients=[email],
                      body=f"Your OTP code is: {otp}",
                      sender=app.config['MAIL_USERNAME'])  # Use dynamic sender email from config

        try:
            # Send the email
            mail.send(msg)
            flash("OTP sent to your email")
            return redirect(url_for('verify_otp'))
        except Exception as e:
            flash(f"Error sending OTP: {e}")
            return redirect(url_for('login'))

    return render_template('unlock_account.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        saved_otp = session.get('otp')
        user_email = session.get('email')  # Retrieve the email from the session

        if entered_otp == saved_otp:
            # OTP verified, so log the user in
            user = User.query.filter_by(email=user_email).first()

            if user:
                # Assuming successful OTP verification means user is now authenticated
                session['user_id'] = user.id
                flash("OTP verified successfully! You can now login.")
                return redirect(url_for('account_home'))
        else:
            flash("Invalid OTP. Please try again.")
            return redirect(url_for('unlock_account'))

    return render_template('verify_otp.html')


from flask import session, redirect, url_for, flash

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user_id from the session
    flash('You have been logged out.')
    return redirect(url_for('login'))  # Redirect to login page after logout


@app.route('/delete_account', methods=['POST'])
def delete_account():
    """Deletes the user's account from the database and logs them out."""
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)  # Delete the user from the database
            db.session.commit()
            session.pop('user_id', None)  # Remove the user_id from the session
            flash('Your account has been deleted.')
            return redirect(url_for('login'))  # Redirect to login page after account deletion
    flash('User not found.')
    return redirect(url_for('login')) 

if __name__ == '__main__':
    app.run(debug=True)
