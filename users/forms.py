from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import Email
from wtforms.validators import ValidationError


def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"

    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(f"Character {char} is not allowed.")


class RegisterForm(FlaskForm):

    email = EmailField(validators=[Email()])
    firstname = StringField(validators=[character_check])
    lastname = StringField(validators=[character_check])
    phone = StringField()
    password = PasswordField()
    confirm_password = PasswordField()
    submit = SubmitField()
