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

    if form.validate_on_submit():
        text_file = open(r"usertext.txt", "w+")
        text_file.write(form.body.data)
        with open("usertext.txt", "r") as file:
            content = file.read()
        text_file.close()

        f = open("../results.txt", "w")
        subprocess.call(["./a.out", "./usertext.txt", "./wordlist.txt"], stdout=f)
        f.close()
        return redirect(url_for('spell_check'))
    return render_template('spell_check.html', title='Spell Check', form=form)



@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('spell_check'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        twofactor = form.twofactor.data
        user = User(username=form.username.data, password=hashed_password, twofactor=twofactor)
        db.session.add(user)
        db.session.commit()
        success_message = 'Success! Your account has been created. Please log in!'
        return redirect(url_for('login'))
    else:
        success_message = 'Failure! Your account has not been created. Does this account already exist?'
    return render_template('register.html', title='Register', form=form,  success=success_message)


@app.route("/", methods=['GET', 'POST'])
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('spell_check'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data) and (user.twofactor == form.twofactor.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            success_message = 'Success'
            return redirect(next_page) if next_page else redirect(url_for('spell_check'))
        else:
            success_message = 'Failure'

    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))



