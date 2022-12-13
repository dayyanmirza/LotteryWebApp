from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import Email, DataRequired, EqualTo
from wtforms.validators import ValidationError
import re
from wtforms.validators import Length


# Checks if user inputted these characters and returns and error if they did.
def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"

    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(f"Character {char} is not allowed.")


# Check user inputted phone number in correct format
def validate_data(form, phone_field):
    p = re.compile("[0-9]{4}-[0-9]{3}-[0-9]{4}")
    if not p.match(phone_field.data):
        raise ValidationError("Must be digits of the form: XXXX-XXX-XXXX (including the dashes)")


# Checks if user has met the criteria for the password they inputted
def validate_password(form, password_field):
    p = re.compile(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)')
    if not p.match(password_field.data):
        raise ValidationError("Must be between 6 and 12 characters in length. Must contain at least 1 digit. Must "
                              "contain at least 1 lowercase word character. Must "
                              "contain at least 1 uppercase word character. Must contain at least 1 special character "
                              "(non-word character). ")


class RegisterForm(FlaskForm):
    email = EmailField(validators=[DataRequired(), Email()])
    firstname = StringField(validators=[DataRequired(), character_check])
    lastname = StringField(validators=[DataRequired(), character_check])
    phone = StringField(validators=[DataRequired(), validate_data])
    password = PasswordField(validators=[DataRequired(), Length(min=6, max=12), validate_password])
    confirm_password = PasswordField(validators=[DataRequired(), Length(min=6, max=12), EqualTo('password',
                                                                                                message='Both '
                                                                                                        'passwords '
                                                                                                        'must be '
                                                                                                        'equal!')])
    submit = SubmitField(validators=[DataRequired()])


class LoginForm(FlaskForm):
    username = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField()
    # recaptcha = RecaptchaField()
    pin = StringField(validators=[DataRequired(), Length(min=6, max=6)])
