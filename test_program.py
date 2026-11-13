import hashlib
import runpy

import pytest

from program import AccessControl, Admin, Guest, RegularUser, User


@pytest.fixture
def system():
    return AccessControl()


# --- User.__init__ / _hash ---
def test_user_stores_hash_not_plain_password():
    user = User("ivan", "qwerty")
    assert user._password_hash != "qwerty"
    assert user._password_hash == hashlib.sha256(b"qwerty").hexdigest()


def test_user_default_access_level():
    assert User("ivan", "pw").access_level == 1


def test_hash_is_deterministic():
    assert User._hash("abc") == User._hash("abc")
    assert User._hash("abc") != User._hash("abd")


# --- check_password ---
def test_check_password_correct():
    assert User("ivan", "qwerty").check_password("qwerty") is True


def test_check_password_wrong():
    assert User("ivan", "qwerty").check_password("wrong") is False


# --- __str__ ---
def test_str_user():
    assert str(User("ivan", "pw")) == "User(username='ivan', level=1)"


def test_str_admin_uses_class_name():
    assert str(Admin("root", "pw")) == "Admin(username='root', level=3)"


# --- Підкласи ---
@pytest.mark.parametrize(
    "cls, level", [(Guest, 1), (RegularUser, 2), (Admin, 3)]
)
def test_subclass_access_levels(cls, level):
    user = cls("name", "pw")
    assert user.access_level == level
    assert isinstance(user, User)


def test_subclass_password_check():
    admin = Admin("admin", "admin123")
    assert admin.check_password("admin123")
    assert not admin.check_password("nope")


# --- add_user ---
def test_add_user_success(system):
    user = RegularUser("ivan", "qwerty")
    assert system.add_user(user) is True
    assert system.users["ivan"] is user


def test_add_user_duplicate(system, capsys):
    system.add_user(Guest("ivan", "a"))
    assert system.add_user(Guest("ivan", "b")) is False
    assert "уже існує" in capsys.readouterr().out
    assert len(system.users) == 1


# --- authenticate_user ---
def test_authenticate_success(system):
    user = RegularUser("ivan", "qwerty")
    system.add_user(user)
    assert system.authenticate_user("ivan", "qwerty") is user


def test_authenticate_wrong_password(system):
    system.add_user(RegularUser("ivan", "qwerty"))
    assert system.authenticate_user("ivan", "wrong") is None


def test_authenticate_unknown_user(system):
    assert system.authenticate_user("petro", "123") is None


# --- демонстраційний блок __main__ ---
def test_main_block_output(capsys):
    runpy.run_module("program", run_name="__main__")
    out = capsys.readouterr().out
    assert "RegularUser(username='ivan', level=2)" in out
    assert out.count("Невдача") == 2