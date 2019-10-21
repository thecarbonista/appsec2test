from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from .models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username', id='uname',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', id='pword', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    twofactor = StringField('Two Factor', id='2fa', validators=[DataRequired(), Length(10)])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(id='success', 'failure')
        else:
            return StringField(id='success', 'success')


class LoginForm(FlaskForm):
    username = StringField('Username', id='uname',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', id='pword', validators=[DataRequired()])
    twofactor = StringField('Two Factor', id='2fa', validators=[DataRequired(), Length(10)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ContentForm(FlaskForm):
    body = StringField(u'Text', widget=TextArea())
    submit = SubmitField('Spell Check')

