from flask import Blueprint, redirect, render_template, request, flash, url_for
from flask.sansio.app import App
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
import logging
import bcrypt
from typing import Optional, cast

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
        username: str = request.form["username"].strip()
        password: bytes = request.form["password"].strip().encode(encoding="utf-8")
        firstname: str = request.form["firstname"].strip()
        lastname: str = request.form["lastname"].strip()

        errors = []

        if not firstname:
            errors.append("Firstname can't be empty.")
        if not lastname:
            errors.append("Lastname can't be empty.")
        if not username:
            errors.append("Username can't be empty.")

        if len(firstname) > 255:
            errors.append("Firstname is too long.")
        if len(lastname) > 255:
            errors.append("Lastname is too long.")
        if len(username) > 255:
            errors.append("Username is too long.")

        if errors:
            for msg in errors:
                flash(msg, "error")
            return redirect(url_for('app_account.signup'))

        password_salt: bytes = bcrypt.gensalt()
        password_hash: bytes = bcrypt.hashpw(password=password, salt=password_salt)
        
        encryption_salt: bytes = generate_salt()
        data_key: bytes = generate_data_key()
        encrypted_data_key: bytes = encrypt(data=data_key, key=derive_key(password, encryption_salt))
       

        new_app_account: AppAccount = AppAccount(
            username = username,
            password_hash = password_hash,
            firstname = firstname,
            lastname = lastname,
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
            logger.error(msg="Username already exist!")
            flash("Username already exist.", "error")
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
        username: str = request.form["username"].strip()
        password: bytes = request.form["password"].strip().encode(encoding="utf-8")

        account_entry = AppAccount.query.filter(AppAccount.username == username).one_or_none()

        if not account_entry:
            logger.error(msg="Invalid username or password.")
            flash("Invalid username or password.", "error")
            return redirect(url_for('app_account.login'))
        
        correct_password: bool = bcrypt.checkpw(password=password, hashed_password=account_entry.password_hash)
        if not correct_password:
            logger.error(msg="Invalid username or password.")
            flash("Invalid username or password.", "error")
            return redirect(url_for('app_account.login'))

        if not login_user(account_entry):
            logger.error(msg="User is banned!")
            flash("User is banned!", "error")
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
    user_keys.pop(current_user.id)
    logout_user()
    return render_template('login.html')


@app_account_bp.route(rule="/account/profile", methods=["POST"])
@login_required
def update_profile():
    firstname: str = request.form.get("firstname", default="").strip()
    lastname: str = request.form.get("lastname", default="").strip()
    
    errors: list[str] = []

    if not firstname:
        errors.append("Firstname can't be empty!")
    if not lastname:
        errors.append("Lastname can't be empty!")

    if len(firstname) > 255:
        errors.append("Firstname is too long!")
    if len(lastname) > 255:
        errors.append("Lastname is too long!")
    
    if errors:
        for msg in errors:
            flash(msg, "error")
            logger.error(msg)
        return redirect(url_for("settings.settings_page", page="account"))

    current_user.firstname = firstname
    current_user.lastname = lastname

    try:
        db.session.commit()
        logger.info("Profile Successfully updated!")
        flash("Profile Successfully updated!", "success")
    except Exception:
        db.session.rollback()
        logger.error("Failed to save changes. Please try again.")
        flash("Failed to save changes. Please try again.", "error")

    return redirect(url_for("settings.settings_page", page="account"))
    
@app_account_bp.route(rule="/account/username", methods=["POST"])
@login_required
def update_username():
    username: str = request.form.get("username", default="").strip()

    errors: list[str] = []

    if not username:
        errors.append("Username can't be empty!")

    if len(username) > 255:
        errors.append("Username is too long!")

    if current_user.username == username:
        errors.append("This is already your current username!")

    if errors:
        for msg in errors:
            flash(msg, "error")
        return redirect(url_for("settings.settings_page", page="account")) 

    current_user.username = username
    try:
        db.session.commit()
        logger.info("Username successfully changed!")
        flash("Username successfully changed!", "success")
    except IntegrityError:
        db.session.rollback()
        logger.error("Username already exists!")
        flash("Username already exists!", "error")

    return redirect(url_for("settings.settings_page", page="account")) 

@app_account_bp.route(rule="/account/password", methods=["POST"])
@login_required
def update_password():
    current_password: bytes = request.form["current_password"].strip().encode(encoding="utf-8")
    new_password: bytes = request.form["new_password"].strip().encode(encoding="utf-8")
    new_password_confirm: bytes = request.form["new_password_confirm"].strip().encode(encoding="utf-8")
    
    errors: list[str] = []

    if not new_password == new_password_confirm:
        logger.error(msg="Please make sure both password fields are identical!")
        errors.append("Please make sure both password fields are identical!")

    correct_current_password: bool = bcrypt.checkpw(password=current_password, hashed_password=current_user.password_hash)
    if not correct_current_password:
        logger.error(msg="Invalid current password!")
        errors.append("Invalid current password!")
    
    identical_password: bool = bcrypt.checkpw(password=new_password, hashed_password=current_user.password_hash)
    if identical_password:
        logger.error(msg="This is already your current password!")
        errors.append("This is already your current password!")

    if errors:
        for msg in errors:
            flash(msg, "error")
        return redirect(url_for("settings.settings_page", page="account")) 

    new_password_salt: bytes = bcrypt.gensalt()
    new_password_hash: bytes = bcrypt.hashpw(password=new_password, salt=new_password_salt)

    data_key: Optional[bytes] = user_keys.get(current_user.id, None)

    if not data_key:
        logger.error("Datakey doesn't exist!")
        logout_user()
        return render_template('login.html')


    new_encryption_salt: bytes = generate_salt()
    new_encrypted_data_key: bytes = encrypt(data=data_key, key=derive_key(new_password, new_encryption_salt))

    current_user.password_hash = new_password_hash
    current_user.encryption_salt = new_encryption_salt
    current_user.encrypted_data_key = new_encrypted_data_key

    try: 
        db.session.commit()
        logger.info("Password successfully updated!")
        flash("Password successfully updated!", "success")
        user_keys.pop(current_user.id)
        logout_user()
        return render_template('login.html')

    except Exception:
        db.session.rollback()
        logger.error("Failed to save changes. Please try again.")
        flash("Failed to save changes. Please try again.", "error")
        return redirect(url_for("settings.settings_page", page="account")) 
