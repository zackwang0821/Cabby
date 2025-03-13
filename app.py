from flask import Flask, request, redirect, url_for, render_template, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os
import sys
import ctypes
import pyautogui
import time
import pyperclip
import subprocess
import pygetwindow as gw

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
    command = 'signtool.exe '
    target_program = "Token Logon"
    
    filename = session.get('uploaded_filename', None)
    if filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not argument:
        argument = 'sign /a /fd sha256 /n "Inventec Corporation" /t http://timestamp.digicert.com/scripts/timestamp.dll '        
        command += argument

        if not filename or not os.path.exists(file_path):
            return f"File not found. Please upload it first."

        command += f"{file_path}"
    
        with open("PW.txt", "r", encoding="utf-8") as file:
            password = file.read()
            pyperclip.copy(password)
    
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            time.sleep(2)

            windows = gw.getWindowsWithTitle("")
            for win in windows:
                if target_program.lower() in win.title.lower():
                   print(f"find windows：{win.title}")
                   win.activate()
                   break
            else:
                print(f"windows not found：{target_program}")
        
            pyautogui.hotkey('ctrl', 'v') #PW:Iec+12345678
            pyautogui.press('enter')

            time.sleep(3)
            stdout, stderr = process.communicate()
            return_code = process.returncode

        except Exception as e:
            print(f"unexcept error：{e}")
            return -1, "", str(e)
    
      # if filename:
      #     if os.path.exists(file_path):
      #         os.remove(file_path)
      #         session.pop('uploaded_filename', None)
          
    else:
        print('Executing app with argument: ' + argument, 'info')
        command += argument
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            return_code = process.returncode

        except Exception as e:
            
            print(f"unexcept error：{e}")
            return -1, "", str(e)

    redirect(url_for('index'))
    
    if return_code == 0:
        return stdout
    else:
        return stderr

def elevate_to_admin():
    """Re-run the script as an administrator."""
    if os.name == 'nt':  # Windows only
        params = ' '.join(sys.argv)  # Get script arguments
        os.system(f'powershell Start-Process python -Verb RunAs -ArgumentList "{params}"')
        sys.exit()  # Exit current instance

    # Check if the script is running as admin
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Re-running as administrator...")
            elevate_to_admin()
    except Exception as e:
        print(f"Admin check failed: {e}")

if __name__ == '__main__':
    
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            elevate_to_admin()
    except Exception as e:
        print(f"Error: {e}")
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(host='0.0.0.0', port=8000)
