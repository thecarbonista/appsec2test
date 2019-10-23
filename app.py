from flask import render_template, url_for, flash, redirect, request, Markup
from . import app, db, bcrypt
from .forms import RegistrationForm, LoginForm, ContentForm
from .models import User
from flask_login import login_user, current_user, logout_user, login_required
import subprocess

@app.route("/spell_check", methods=['GET', 'POST'])
@login_required
def spell_check():
    form = ContentForm()
    content = 'Results will display here'

    if form.validate_on_submit():
        text_file = open(r"usertext.txt", "w+")
        text_file.write(form.body.data)
        text_file.close()

        f = open("results.txt", "w+")
        subprocess.call(["./a.out", "./usertext.txt", "./wordlist.txt"], stdout=f)
        content = f.read()
        f.close()

        return redirect(url_for('spell_check', text=content))
    return render_template('spell_check.html', title='Spell Check', form=form, text=content)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        success_message = 'Success'
    form = RegistrationForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            twofactor = form.twofactor.data
            user = User(username=form.username.data, password=hashed_password, twofactor=twofactor)
            db.session.add(user)
            db.session.commit()
            success_message = 'Success'
        else:
            success_message = 'Failure'
    else:
        success_message = ''

    return render_template('register.html', title='Register', form=form,  success=success_message)


@app.route("/", methods=['GET', 'POST'])
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        success_message = 'Success'
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data) and (user.twofactor == form.twofactor.data):
            login_user(user)
            success_message = 'Success'
        else:
            success_message = 'Failure'
    if request.method == 'GET':
        success_message = ''
    return render_template('login.html', title='Login', form=form, result=success_message)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))



