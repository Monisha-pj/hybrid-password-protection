#  Secure Flask Password Manager with Argon2 & OTP Unlock

A secure and user-friendly password management web application built using **Flask**, **Argon2**, and **Flask-Mail**. It includes strong password enforcement, hashing, auto rehashing, OTP-based account unlocking, and more.



##  Features

-  **User Registration with Strong Password Validation**
   - At least 1 uppercase, 1 digit, 1 special character.
  
-  **Password Hashing using Argon2**
   - Secure and modern password hashing algorithm.
  
-  **Automatic Rehashing**
   - Passwords rehashed every 30 days or each login.
  
-  **User Login with Failed Attempt Tracking**
   - Locks account after 3 failed attempts.

-  **OTP-Based Account Unlocking**
   - Generates OTP and sends to email for verification.

-  **Password Update Feature**
   - Old password verification + new password strength check.

-  **Flask-Mail Integration**
   - Sends OTP securely through configured SMTP email.

-  **Account Dashboard**
   - Displays user details after login.

-  **Account Deletion**
   - Permanently deletes user account from the database.

-  **Session Management**
   - Secures user login using Flask sessions.



##  Tech Stack

| Tech          | Purpose                             |
|---------------|-------------------------------------|
| **Python**    | Core backend language               |
| **Flask**     | Web framework                       |
| **Flask-Mail**| Sending OTP email                   |
| **Argon2**    | Password hashing & rehashing        |
| **SQLite**    | Lightweight database via SQLAlchemy |
| **HTML/CSS**  | Frontend templates                  |
