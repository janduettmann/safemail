from flask import Blueprint, redirect, render_template, request, flash, url_for
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.exc import IntegrityError
import logging
import bcrypt
from typing import cast

from app.models import AppAccount, MailAccount
from app.extensions import db, user_keys
from app.crypt_util import generate_salt, generate_data_key, encrypt, decrypt, derive_key

logger = logging.getLogger(name=__name__)

app_account_bp: Blueprint = Blueprint(name="app_account", import_name=__name__)

@app_account_bp.route(rule="/signup", methods=["POST", "GET"])
def signup():
    """Handle user registration.

    GET: Render the signup form.
    POST: Create a new AppAccount with hashed password and encrypted data key,
    then redirect to the mail account setup page.
    """
    if request.method == "POST":
        username: str = request.form["username"]
        password: bytes = request.form["password"].encode(encoding="utf-8")

        password_salt: bytes = bcrypt.gensalt()
        password_hash: bytes = bcrypt.hashpw(password=password, salt=password_salt)
        
        encryption_salt: bytes = generate_salt()
        data_key: bytes = generate_data_key()
        encrypted_data_key: bytes = encrypt(data=data_key, key=derive_key(password, encryption_salt))
       

        new_app_account: AppAccount = AppAccount(
            username = username,
            password_hash = password_hash,
            encryption_salt = encryption_salt,
            encrypted_data_key = encrypted_data_key
        )

        try:
            db.session.add(instance=new_app_account)
            db.session.commit()
            user_keys[new_app_account.id] = data_key
            logger.info(msg="Successfully created account!")
            return redirect(url_for('mail_account.add_mail_account'))
        except IntegrityError:
            db.session.rollback()
            logger.error(msg="Account already exist!")
            flash("Account already exist.")
            return redirect(url_for('app_account.signup'))

    return render_template("signup.html")

@app_account_bp.route(rule="/login", methods=["POST", "GET"])
def login():
    """Handle user login.

    GET: Render the login form.
    POST: Verify credentials, derive the encryption key, store the data key
    in the in-memory user_keys dict, and redirect to home or mail account setup.
    """
    if request.method == "POST":
        username: str = request.form["username"]
        password: bytes = request.form["password"].encode(encoding="utf-8")

        account_entry = AppAccount.query.filter(AppAccount.username == username).one_or_none()

        if not account_entry:
            logger.error(msg="Invalid username or password.")
            flash("Invalid username or password.")
            return redirect(url_for('app_account.login'))
        
        correct_password: bool = bcrypt.checkpw(password=password, hashed_password=account_entry.password_hash)
        if not correct_password:
            logger.error(msg="Invalid username or password.")
            flash("Invalid username or password.")
            return redirect(url_for('app_account.login'))

        if not login_user(account_entry):
            logger.error(msg="User is banned!")
            flash("User is banned!")
            return redirect(url_for('app_account.login'))  

        derived_key: bytes = derive_key(password=password, salt=account_entry.encryption_salt)
        data_key: bytes = decrypt(chiffre=account_entry.encrypted_data_key, key=derived_key)
        user_keys[account_entry.id] = data_key 
        mail_account_entry = MailAccount.query.filter(MailAccount.owner_id == account_entry.id).all()
        
        if len(mail_account_entry) > 0:
            return redirect(url_for('home.home'))
    
        return redirect(url_for('mail_account.add_mail_account'))

    return render_template("login.html")

@app_account_bp.route(rule="/logout", methods=["POST"])
@login_required
def logout():
    """Log the user out and remove their data key from the in-memory store."""
    app_account = cast(AppAccount, current_user)
    user_keys.pop(app_account.id, None)
    logout_user()
    return render_template('login.html')
