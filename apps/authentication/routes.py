# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import render_template, redirect, request, url_for, flash
from flask_login import (
    current_user,
    login_user,
    logout_user,login_required
)

from flask_dance.contrib.github import github
from flask_dance.contrib.google import google
from apps import db, login_manager
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm
from apps.authentication.models import Users, Role, Permission, LoginLog
from apps.config import Config
from apps.authentication.util import verify_pass
from apps.authentication.forms import UserForm, DeleteForm, ForgotPasswordForm, PasswordResetForm, RoleForm, PermissionForm
from werkzeug.utils import secure_filename
import os
from apps.authentication.email import send_reset_email
from apps.authentication.token import verify_reset_token

@blueprint.route('/login-logs')
@login_required
def view_login_logs():
    logs = LoginLog.query.order_by(LoginLog.login_time).all()  # ascending order
    form = DeleteForm()
    return render_template('accounts/login_logs.html', login_logs=logs, form=form)


@blueprint.route('/login-logs/delete/<int:log_id>', methods=['POST'])
def delete_login_log(log_id):
    log = LoginLog.query.get_or_404(log_id)
    db.session.delete(log)
    db.session.commit()
    flash('Login log deleted successfully.', 'success')
    return redirect(url_for('authentication_blueprint.view_login_logs'))

@blueprint.route('/users_table')
def users_table():
    our_users = Users.query.options(
        db.joinedload(Users.role).joinedload(Role.permissions)
    ).all()

    print(our_users)
    return render_template('accounts/users_table.html',segment = 'index',our_users=our_users)

@blueprint.before_app_request
def setup_roles_permissions():
    assign_permissions_to_roles()

def assign_permissions_to_roles():

    permissions = {
        'create_post': 'Create new posts',
        'edit_post': 'Edit existing posts',
        'delete_post': 'Delete posts',
        'view_post': 'View posts',
        'read_posts': 'Read posts',
        'manage_roles': 'Manage roles',
        'manage_users': 'Manage users'
    }
    for name, description in permissions.items():
        permission = Permission.query.filter_by(name=name).first()
        if not permission:
            permission = Permission(name=name, description=description)
            db.session.add(permission)
        else:
            if permission.description != description:
                permission.description = description


    roles = {
        'Admin': {
            'description': 'Administrator with full access',
            'permissions': ['create_post', 'edit_post', 'delete_post', 'view_post','manage_roles', 'manage_users']
        },
        'Editor': {
            'description': 'Can create,edit and view_posts',
            'permissions': ['create_post', 'edit_post', 'view_post']
        },
        'Viewer': {
            'description': 'Regular viewer with basic access',
            'permissions': ['view_post']
        },
        'User':{
            'description': 'User with basic access',
            'permissions': ['read_post']
        }
        }
    for name, data in roles.items():
        role = Role.query.filter_by(name=name).first()
        if not role:
            role = Role(name=name, description=data['description'])
            db.session.add(role)
        else:
            if role.description != data['description']:
                role.description = data['description']
  
    for perm_name in data['permissions']:
        permission = Permission.query.filter_by(name=perm_name).first()
        if permission and permission not in role.permissions:
            role.permissions.append(permission)
    db.session.commit()

@blueprint.route('/roles/edit/<int:id>', methods=['GET', 'POST'])
def edit_role(id):
    role = Role.query.get_or_404(id)
    form = RoleForm()
    
    # Set choices for permissions field
    form.permissions.choices = [(p.id, p.name) for p in Permission.query.all()]
    
    if request.method == 'POST' and form.validate_on_submit():
        new_name = form.name.data.strip()
        description = form.description.data.strip() if form.description.data else ""
        perm_ids = form.permissions.data or []  # Handle None case
        
        # Validation: name cannot be empty
        if not new_name:
            flash('Role name cannot be empty.', 'danger')
            return render_template('accounts/edit_role.html', 
                                 role=role, 
                                 form=form, 
                                 permissions=Permission.query.all())
        
        # Check if new name already exists (and is not the current role's name)
        existing_role = Role.query.filter_by(name=new_name).first()
        if existing_role and existing_role.id != role.id:
            flash('Role name already exists.', 'warning')
            return render_template('accounts/edit_role.html', 
                                 form=form, 
                                 role=role, 
                                 permissions=Permission.query.all())
        
        # Update fields
        role.name = new_name
        role.description = description
        
        # Update permissions relationship
        if perm_ids:
            selected_perms = Permission.query.filter(Permission.id.in_(perm_ids)).all()
            role.permissions = selected_perms
        else:
            # Clear all permissions if none selected
            role.permissions = []
        
        try:
            db.session.commit()
            flash('Role updated successfully.', 'success')
            return redirect(url_for('authentication_blueprint.role_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating role: {str(e)}', 'danger')
            return render_template('accounts/edit_role.html', 
                                 form=form, 
                                 role=role, 
                                 permissions=Permission.query.all())
    
    elif request.method == 'GET':
        # Pre-fill the form with current role data
        form.name.data = role.name
        form.description.data = role.description
        form.permissions.data = [p.id for p in role.permissions]
    
    # For both GET and failed POST validation
    return render_template('accounts/edit_role.html', 
                         form=form, 
                         role=role, 
                         permissions=Permission.query.all())


@blueprint.route('/roles/delete/<int:id>', methods=['GET','POST'])
def delete_role(id):
    role = Role.query.get_or_404(id)
    
    if role.users:  # role.users is a list of users having this role
        flash('Cannot delete role assigned to users. Reassign or delete those users first.', 'warning')
        return redirect(url_for('authentication_blueprint.role_list'))
    
    try:
        db.session.delete(role)
        db.session.commit()
        flash('Role deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting role: {str(e)}', 'danger')
    
    return redirect(url_for('authentication_blueprint.role_list'))


@blueprint.route('/roles')
def role_list():
    if current_user.has_permission('manage_roles'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home_blueprint.index'))
    
    roles = Role.query.all()
    return render_template('accounts/roles_list.html', roles=roles)

@blueprint.route('/permissions/edit/<int:id>', methods=['GET', 'POST'])
def edit_permission(id):
    permission = Permission.query.get_or_404(id)

    if request.method == 'POST':
        form = PermissionForm(request.form, obj=permission)  # Ensure form uses submitted data
        if form.validate_on_submit():
            existing_permission = Permission.query.filter_by(name=form.name.data.strip()).first()
            if existing_permission and existing_permission.id != permission.id:
                flash('Permission name already exists.', 'warning')
                return render_template('accounts/edit_permission.html', form=form, permission=permission)

            # Populate the permission object with form data
            form.populate_obj(permission)
            permission.name = permission.name.strip()
            permission.description = permission.description.strip() if permission.description else ""

            try:
                db.session.commit()
                flash('Permission updated successfully.', 'success')
                return redirect(url_for('authentication_blueprint.permission_list'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating permission: {str(e)}', 'danger')
        else:
            flash('Form validation failed.', 'danger')
    else:
        form = PermissionForm(obj=permission)  # GET: pre-fill form

    return render_template('accounts/edit_permission.html', form=form, permission=permission)


@blueprint.route('/permissions/delete/<int:perm_id>', methods=['POST', 'GET'])
def delete_permission(perm_id):
    permission = Permission.query.get_or_404(perm_id)
       
    if permission.roles:  # permission.roles is a list of roles having this permission
        flash('Cannot delete permission assigned to roles. Remove from roles first.', 'warning')
        return redirect(url_for('authentication_blueprint.permission_list'))
    try:
        db.session.delete(permission)
        db.session.commit()
        flash('Permission deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting permission: {str(e)}', 'danger')

    return redirect(url_for('authentication_blueprint.permission_list'))

@blueprint.route('/permissions')
def permission_list():
    if current_user.has_permission('manage_permissions'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home_blueprint.index'))
    
    permissions = Permission.query.all()
    return render_template('accounts/permissions_list.html', permissions=permissions)

@blueprint.route('/User/Profile')
def User_profile():
    users = Users.query.all()
    return render_template('accounts/User_profile.html', segment = 'index', users=users)

@blueprint.route('/delete/<aPath>/<int:id>')
def delete(aPath,id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        # flash("User Deleted Successfully!1")
        # our_users = Users.query.order_by(Users.date_added)
        # return render_template("accounts/add_user.html", form=form, name=name, our_users=our_users)
    except Exception as e:
        db.session.rollback()
    
    finally:
        our_users = Users.query.order_by(Users.date_added)
        flash("User Deleted Successfully!!")
        return render_template("accounts/users_table.html", form=form, name=name, our_users=our_users)
    # except:
    #     flash("Oops! There wasa a problem deleting user, try again..")
    #     return render_template("accounts/add_user.html", form=form, name=name, our_users=our_users)

@blueprint.route('/update/<aPath>/<int:id>', methods=['GET', 'POST'])
def update(aPath, id):
    user = Users.query.get_or_404(id)
    form = UserForm(obj=user)  # Pre-fill form fields with existing user data

    # Populate role dropdown with available roles
    form.role.choices = [(role.id, role.name) for role in Role.query.all()]
    form.permissions.choices = [(perm.id, perm.name) for perm in Permission.query.all()]

    if request.method == 'POST' and form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.role_id = form.role.data

        if form.profile_image.data:
            filename = secure_filename(form.profile_image.data.filename)
            image_path = os.path.join('static/assets/img', filename)
            form.profile_image.data.save(image_path)
            user.profile_image = filename
        
        selected_perm_ids = form.permissions.data 
        perms = Permission.query.filter(Permission.id.in_(selected_perm_ids)).all()

        try:
            db.session.commit()
            flash("User updated successfully!", "success")
            return render_template("accounts/update_user.html", form=form, name_to_update=user)

        except Exception as e:
            db.session.rollback()
            flash(f"Error updating user: {str(e)}", "danger")
            return render_template("accounts/update_user.html", form=form, name_to_update=user)
    print (form.errors)

    return render_template("accounts/update_user.html", form=form, name_to_update=user, id=id)

@blueprint.route('/user/add', methods=['GET', 'POST'])
def add_user():
    username = None
    form = UserForm()
    # Populate role dropdown
    form.role.choices = [(role.id, role.name) for role in Role.query.all()]
    form.permissions.choices = [(perm.id, perm.name) for perm in Permission.query.all()]

    if form.validate_on_submit():
           # Save profile image if uploaded
        image_file = 'default.jpg'
        if form.profile_image.data:
            filename = secure_filename(form.profile_image.data.filename)
            image_path = os.path.join('static/assets/img', filename)
            form.profile_image.data.save(image_path)
            image_file = filename

        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            user = Users(username=form.username.data, email=form.email.data,
                         password= form.password.data, profie_image=image_file, role_id=form.role.data)
        
        selected_perm_ids = form.permissions.data 
        perms = Permission.query.filter(Permission.id.in_(selected_perm_ids)).all()

            
        db.session.add(user)
        db.session.commit()

        username = form.username.data
        form.username.data = ''
        form.email.data = ''
        form.password.data =''
        form.profile_image.data =''
        form.role.data = ''
        flash("User Added Successfully")

    else:
        print(form.errors)

    
    our_users = Users.query.order_by(Users.date_added)
    return render_template("accounts/add_user.html", form=form, username=username, our_users=our_users,segment ='index')


@blueprint.route('/')
def route_default():
    return redirect(url_for('home_blueprint.posts'))


# Login & Registration

@blueprint.route("/github")
def login_github():
    """ Github login """
    if not github.authorized:
        return redirect(url_for("github.login"))

    res = github.get("/user")
    return redirect(url_for('home_blueprint.index'))


@blueprint.route("/google")
def login_google():
    """ Google login """
    if not google.authorized:
        return redirect(url_for("google.login"))

    res = google.get("/oauth2/v1/userinfo")
    return redirect(url_for('home_blueprint.index'))


@blueprint.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if request.method == 'POST':
        email = request.form['email']
        user = Users.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
        flash('Check your email for a password reset link.', 'info')
        return redirect(url_for('authentication_blueprint.login'))
    return render_template('accounts/forgot_password.html', form = form)

@blueprint.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    email = verify_reset_token(token)
    if not email:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('authentication_blueprint.forgot_password'))
    form = PasswordResetForm()
    if request.method == 'POST':
        password = request.form['password']
        user = Users.query.filter_by(email=email).first()
        user.set_password(password)  # Make sure you hash the password!
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('authentication_blueprint.login'))
    return render_template('accounts/reset_password.html', form= form)

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
     
    login_form = LoginForm()

    if login_form.validate_on_submit():
        username = login_form.username.data
        password = login_form.password.data

        # Locate user
        user = Users.query.filter_by(username=username).first()
        ip = request.remote_addr
        ua = request.headers.get('User-Agent')
    

        # Check the password
        if user and verify_pass(password, user.password):
            log = LoginLog(user_id=user.id, ip_address=ip, user_agent=ua, successful=True)
            db.session.add(log)
            db.session.commit()

            login_user(user)
            return redirect(url_for('home_blueprint.index'))
        
        else:
            # Log failed login attempt - user might be None
            user_id = user.id if user else None
            log = LoginLog(user_id=user_id, ip_address=ip, user_agent=ua, successful=False)
            db.session.add(log)
            db.session.commit()
            return render_template('accounts/login.html',
                               msg='Wrong user or password',
                               form=login_form)

    if not current_user.is_authenticated:
        return render_template('accounts/login.html',
                               form=login_form)
    return redirect(url_for('home_blueprint.index'))


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']

        # Check usename exists
        user = Users.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Username already registered',
                                   success=False,
                                   form=create_account_form)

        # Check email exists
        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Email already registered',
                                   success=False,
                                   form=create_account_form)

        # else we can create the user
        user = Users(**request.form)
        db.session.add(user)
        db.session.commit()

        return render_template('accounts/register.html',
                               msg='User created please <a href="/login">login</a>',
                               success=True,
                               form=create_account_form)

    else:
        return render_template('accounts/register.html', form=create_account_form)


@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login'))


# Errors

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500

@blueprint.context_processor
def has_github():
    return {'has_github': bool(Config.GITHUB_ID) and bool(Config.GITHUB_SECRET)}

@blueprint.context_processor
def has_google():
    return {'has_google': bool(Config.GOOGLE_ID) and bool(Config.GOOGLE_SECRET)}