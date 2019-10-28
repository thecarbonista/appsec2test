import pytest
from .models import User

@pytest.fixture(scope='module')
def user():
    user = User(username='test', password='password', twofactor='0000000000')
    return user

@pytest.fixture(scope='module')
def lookup():
    username = User.query.filter_by(username=form.username.data).first()
    return username