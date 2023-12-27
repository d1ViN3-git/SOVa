from flask import request, redirect, flash, render_template, url_for, session
from flask_login import login_user, current_user
from flask_bcrypt import generate_password_hash, check_password_hash
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError,
)
from .auth.forms import login_form, register_form
from .models import db
from .models.models import User
from . import create_app, login_manager

app = create_app()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def home():
    return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = login_form()
    
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect('/admin/')
            else:
                flash("Invalid Username or password!", "danger")
        except Exception as e:
            flash(e, "danger")

    return render_template("auth/auth.html")

@app.route("/register/", methods=("GET", "POST"), strict_slashes=False)
def register():
    if current_user.username == 'admin':
        form = register_form()
        if form.validate_on_submit():
            try:
                password = form.password.data
                username = form.username.data
                
                newuser = User(
                    username=username,
                    password=generate_password_hash(password).decode('utf-8'),
                )
                db.session()
                db.session.add(newuser)
                db.session.commit()
                flash(f"Account Succesfully created", "success")
                return redirect(url_for("login"))

            except InvalidRequestError:
                db.session.rollback()
                flash(f"Something went wrong!", "danger")
            except IntegrityError:
                db.session.rollback()
                flash(f"User already exists!.", "warning")
            except DataError:
                db.session.rollback()
                flash(f"Invalid Entry", "warning")
            except InterfaceError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
            except DatabaseError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
        return render_template("register/register.html")
    else:
        return redirect(url_for('login'))
    # flask.flash('Logged in successfully.')
    next = request.args.get('next')
    # url_has_allowed_host_and_scheme should check if the url is safe
    # for redirects, meaning it matches the request host.
    # See Django's url_has_allowed_host_and_scheme for an example.
    # if not url_has_allowed_host_and_scheme(next, request.host):
    #     return flask.abort(400)

