# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField,SelectMultipleField,DateTimeField, BooleanField,TextAreaField
from wtforms.validators import Email, DataRequired, Optional
from flask_wtf.file import FileAllowed
from wtforms.validators import EqualTo, Length
from datetime import datetime

# login and registration


class LoginForm(FlaskForm):
    username = StringField('Username',
                         id='username_login',
                         validators=[DataRequired()])
    password = PasswordField('Password',
                             id='pwd_login',
                             validators=[DataRequired()])


class CreateAccountForm(FlaskForm):
    username = StringField('Username',
                         id='username_create',
                         validators=[DataRequired()])
    email = StringField('Email',
                      id='email_create',
                      validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             id='pwd_create',
                             validators=[DataRequired()])


class UserForm(FlaskForm):
    username = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()]) 
    role = SelectField('Role', coerce=int, validators=[DataRequired()])
    permissions= SelectMultipleField('Permission', coerce=int, validators=[DataRequired()])
    profile_image = FileField('Profile Image', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField("Submit")


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=6, message="Password should be at least 6 characters.")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Reset Password')

class LoginLogForm(FlaskForm):
    login_time = DateTimeField(
        'Login Time',
        default=datetime.utcnow,
        format='%Y-%m-%d %H:%M:%S',  # Important: specify format
        validators=[Optional()]
    )
    ip_address = StringField('IP Address', validators=[Optional()])
    user_agent = StringField('User Agent', validators=[Optional()])
    successful = BooleanField('Successful Login')  # Don't set `default=True` here — WTForms handles it differently

    submit = SubmitField('Submit')


class DeleteForm(FlaskForm):
    submit = SubmitField('Delete')


class RoleForm(FlaskForm):
    name = StringField('Role Name', validators=[DataRequired(), Length(max=50)])
    description = TextAreaField('Description', validators=[Length(max=255)])
    permissions= SelectMultipleField('Permission', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Submit')

class PermissionForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=64)])
    description = StringField('Description', validators=[Length(max=255)])
    submit = SubmitField('Submit')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[
        DataRequired()
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=6)
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')