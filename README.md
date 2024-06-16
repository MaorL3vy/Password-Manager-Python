# Password Manager Application

![Password Manager Application](https://img.shields.io/badge/Password%20Manager%20Application-Python-blue)

## Introduction

This Python script implements a simple password manager application using SQLite for database storage and tkinter for the graphical user interface (GUI).

## Features

- Features
**User Management:**

Register new users with a username and master password.
Authenticate users with their master password.
Password Management:

Add passwords for various services securely.
Retrieve passwords for services.
View all stored passwords.
Delete passwords for services.
Generate random passwords with customizable length.
**Security:**

Passwords are encrypted using the Fernet symmetric encryption scheme from the cryptography library.
Master passwords are hashed using SHA-256 before storing them in the database.
## Installation

To run this application, follow these steps:

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/MaorL3vy/Password-Manager-Python.git
   cd Password-Manager-Python
   ```

2. **Install Dependencies:**

Make sure you have Python 3.x installed. Then, install required dependencies:
   ```bash
   pip install cryptography
   ```

3. **Run the Application:**
```bash
python main.py
```



## Usage
**Registration/Login:**

On launch, you can register a new user or log in with an existing username and master password.
**Main Screen:**

Add passwords, retrieve passwords, view all stored passwords, change master password, and logout.
**Adding Passwords:**

Enter service name, username, and password. Optionally, generate a random password.
**Retrieving Passwords:**

Enter the service name to retrieve the corresponding username and password.
**Viewing Passwords:**

Displays a table of all stored passwords for the logged-in user.
**Deleting Passwords:**

Enter the service name to delete its stored password.
**Changing Master Password:**

Verify the current master password and enter a new one to update.

---

Contributing
Contributions to enhance this Password Manager application are welcome. To contribute:

Fork the repository.
Create a new branch (git checkout -b feature-your-feature-name).
Make your changes and commit them (git commit -m 'Add some feature').
Push to the branch (git push origin feature-your-feature-name).
Open a pull request.

---

## Credits

- Discord: maorl3vy
- Author: Maor Levy
