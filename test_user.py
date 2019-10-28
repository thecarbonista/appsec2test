from .models import User
from . import app, db, bcrypt
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

def test_new_user(user):

    assert user.username == 'test'
    assert user.password == 'password'
    assert user.twofactor =='0000000000'
    assert user.is_authenticated



