from flask import Flask, request, redirect, url_for, render_template, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os
import subprocess

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'Folder'
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
@login_required
def index():
    print('Index route accessed')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print('Form validated')
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print('User found')
            if bcrypt.check_password_hash(user.password, form.password.data):
                print('Password correct')
                login_user(user)
                return redirect(url_for('index'))
            else:
                print('Password incorrect')
        else:
            print('User not found')
        flash('Login Unsuccessful. Please check email and password', 'danger')
    else:
        print('Form not validated')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    if file:
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        session['uploaded_filename'] = file.filename
        
        return 'File uploaded successfully'

@app.route('/execute', methods=['POST'])
@login_required
def execute_app():
    argument = request.form.get('argument', '')
    command = ['hello.exe']
    
    filename = session.get('uploaded_filename', None)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if argument:
        print('Executing app with argument: ' + argument, 'info')
    else :
        argument = 'sign /a /n "InventecCorporation" /t http://timestamp.digicert.com/scripts/timestamp.dll'
    argument = argument.split(' ')
    command.extend(argument)

    if not os.path.exists(file_path):
        return f"File not found. Please upload it first."

    command.extend([file_path])
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        flash('App executed successfully: ' + result.stdout, 'success')
    except subprocess.CalledProcessError as e:
        flash('Failed to execute app: ' + e.stderr, 'danger')
    print(result.stdout)
    redirect(url_for('index'))
    os.remove(file_path)
    return f"App executed successfully: '{filename}'"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(host='0.0.0.0', port=8000)
