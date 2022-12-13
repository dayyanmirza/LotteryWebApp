# IMPORTS
import logging
from datetime import datetime
from flask import request

import bcrypt
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session
from flask_login import login_user, current_user, logout_user, login_required
from markupsafe import Markup


from admin.views import requires_roles
from app import db
from models import User
from users.forms import RegisterForm, LoginForm

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user')

        # logging statement for registration
        logging.warning('SECURITY - User registration [%s, %s]',
                        form.email.data,
                        request.remote_addr
                        )

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # instance of the Login Form class
    form = LoginForm()

    # limit authorisation attempts,
    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.username.data).first()

        # checks - if (user is Null) OR (passwords do not match) equals True, or pinkey is incorrect.
        if not user or not bcrypt.checkpw(form.password.data.encode('utf-8'), user.password) \
                or not pyotp.TOTP(user.pinkey).verify(form.pin.data):

            # Increase authentication attempts by 1
            session['authentication_attempts'] += 1

            # If authentication attempts have reached allowed limit
            if session.get('authentication_attempts') >= 3:
                # logging statement
                logging.warning('SECURITY - Too many login attempts [%s, %s]',
                                form.username.data,
                                request.remote_addr
                                )

                # Send message with reset link
                flash(Markup('Number of incorrect login attempts exceeded. '
                             'Please click <a href="/reset">here</a> to reset.'))
                # Return to login page without form
                return render_template('users/login.html')

            # logging statement for invalid login attempts
            logging.warning('SECURITY - Invalid Log in [%s, %s]',
                            form.username.data,
                            request.remote_addr,
                            )
            # If authentication attempts have not reached allowed limit send message
            flash('Please check your login details and try again,'
                  '{} login attempts remaining'.format(3 - session.get('authentication_attempts')))

        # Logs user in
        login_user(user)

        # last login assigned to current login
        user.last_login = user.current_login

        # assign current_login with the current date and time
        user.current_login = datetime.now()

        # logging statement
        logging.warning('SECURITY - Log in [%s, %s, %s]',
                        current_user.id,
                        current_user.email,
                        request.remote_addr
                        )

        db.session.add(user)
        db.session.commit()

        if current_user.role == 'user':
            return redirect(url_for('users.profile'))
        else:
            return redirect(url_for('admin.admin'))

    # Return to login page with form
    return render_template('users/login.html', form=form)


# Reset the authentication attempts in the session to zero
@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


# view user profile
@users_blueprint.route('/profile')
@login_required
@requires_roles('user')
def profile():
    return render_template('users/profile.html', name="PLACEHOLDER FOR FIRSTNAME")


# view user account
@users_blueprint.route('/account')
@login_required
@requires_roles('user', 'admin')
def account():
    return render_template('users/account.html',
                           acc_no="PLACEHOLDER FOR USER ID",
                           email="PLACEHOLDER FOR USER EMAIL",
                           firstname="PLACEHOLDER FOR USER FIRSTNAME",
                           lastname="PLACEHOLDER FOR USER LASTNAME",
                           phone="PLACEHOLDER FOR USER PHONE")


# view user logout
@users_blueprint.route('/logout')
@login_required
@requires_roles('user', 'admin')
def logout():
    # logging statement
    logging.warning('SECURITY - Log out [%s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    request.remote_addr
                    )
    logout_user()
    return redirect(url_for('index'))
