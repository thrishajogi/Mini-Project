Multi Layer Authentication System

CypherWall is a secure authentication system that uses passwords, security questions, a custom TOTP authenticator app, and a risk-based login system.
This README explains how to set up, run, and test the entire project.

1. Requirements

Before running the project, install:

Node.js (v16+ recommended)

MongoDB Atlas account

Any browser

Android Studio (for mobile authenticator)

2. Clone the Repository
git clone https://thrishajogi@github.com/thrishajogi/Mini-Project.git 
cd zerobank

3. Install Backend Dependencies
cd backend
npm install


Packages used include:
express, mongoose, bcrypt, crypto, cors, nodemailer, dotenv

4. Create .env File

Inside the backend folder, create a file named .env:

MONGO_URI=your_mongodb_atlas_uri
ADMIN_SECRET=your_admin_password


Examples:

MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/ZeroBankDB
ADMIN_SECRET=ZeroBankAdmin123

5. Start Backend Server
node server.js


You should see:

MongoDB Connected to Atlas
Server running on port 5000


The backend will run at:

http://localhost:5000

6. Run the Frontend

The frontend folder contains HTML files such as:

signin.html

security.html

security-login.html

account-summary.html

To run the frontend:

Option A: Use VSCode Live Server

Right-click signin.html → Open with Live Server

Option B: Use a simple HTTP server

Example using Python:

cd frontend
python -m http.server 5500


Then open:

http://localhost:5500/signin.html

7. Testing the Flow
1. Sign Up

Send POST to backend or use your own signup form.

2. Login

Enter email + password in signin.html.

3. Security Question

Answer the security challenge.

4. TOTP Setup

Scan the QR code using your custom authenticator app.

5. MFA Login

Enter the 6-digit TOTP from the mobile app.

6. Account Locking

After 3 wrong attempts:

User is locked

Only admin can unlock

To unlock manually in MongoDB:

isLocked: false
lockUntil: null
failedAttempts: 0

8. Running the Mobile Authenticator

Open the /mobile-app folder in Android Studio.
Run the app on an emulator or a physical phone.

The app will:

Scan QR from the security setup page

Store secret

Generate 6-digit TOTP every 30 seconds

9. Folder Structure
/frontend
/backend
/mobile-app
README.md

10. Summary

This project demonstrates a bank-style authentication system featuring:

Password login

Security questions

Custom TOTP authenticator app

Risk scoring

Device/IP detection

Account lockout

MongoDB Atlas backend
