from flask import Flask, render_template, request, redirect, url_for,abort,flash,send_from_directory
import re
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import os
from sqlalchemy import ForeignKey
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import time
import jwt
from werkzeug.security import generate_password_hash,check_password_hash




#app config

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret'
app.config['UPLOAD_FOLDER'] = 'files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.jinja_env.add_extension('jinja2.ext.loopcontrols')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'mwld92@gmail.com'
app.config['MAIL_PASSWORD'] = 'idkifitismeornot111155'

mail = Mail(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

static_folder = 'static'
app.config['STATIC_FOLDER'] = static_folder


db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User class (Schema)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    workers = db.relationship('Worker', backref='user', lazy=True)
    isAdmin = db.Column(db.Boolean, default=False)

    def get_reset_token(self, expires=1800):
        return jwt.encode({'reset-password': self.id,
                           'exp':    time.time() + expires},
                           key=app.config['SECRET_KEY'])

    def reset_password(self, token, new_password):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return False
        if data['reset-password'] != self.id:
            return False
        self.password = new_password
        db.session.commit()
        return True

    def __repr__(self):
        return '<User %r>' % self.username

class Worker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_no = db.Column(db.String(120), nullable=False)
    job_id = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    job = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(120), nullable=False)
    cv = db.Column(db.String(80), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    timings = db.Column(db.String(120), nullable=False)
    jobs = db.relationship('Jobs', backref='worker', lazy=True)
    def __repr__(self):
        return '<Job %r>' % self.title

class Jobs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jobname = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    timings = db.Column(db.String(120), nullable=False)
    salary = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(120), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('worker.job_id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_user(username, password, email):
    user = User(username=username, password=password, email=email)
    db.session.add(user)
    db.session.commit()
    return user


@app.before_first_request
def create_tables():
    db.create_all()


# authentication

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email= request.form['email']
        password = request.form['pass']
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
                login_user(user,remember=True)
                return redirect(url_for('index', email=email,user=user))
            else:
                flash('Invalid password', 'error')
                print('Invalid password')
        else:
           
            flash('Invalid password', 'error')
            print('Invalid password')
            
    return render_template('login.html', user=current_user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
        elif not EMAIL_REGEX.match(email):
            flash('Invalid email address', 'error')
        else:
            password = generate_password_hash(password,method="sha256")
            
            user1 = User.query.filter_by(username=username).first()
            if user1 is None:
                user = create_user(username, password, email)
                login_user(user, remember=True)
                return redirect(url_for('index', email=email, user=user))
            if user1:
                flash ('Username already exists', 'error')
                print('Username already exists')
            else:
                create_user(username, password, email)
                login_user(user1,remember=True)
                flash('User created', 'success')
                print('User created')
                return redirect(url_for('login'))

    return render_template('signup.html', user=current_user)

@app.route('/upload_job', methods=['GET', 'POST'])
@login_required
def upload_job():
    if request.method == 'POST':
        name = request.form['username']
        email = request.form['email']
        job = request.form['job']
        contact_no = request.form['contact_no']
        description = request.form['description']
        category = request.form['category']
        location = request.form['location']
        timings = request.form['timings']
        file = request.files['filename']
        if name and email and job and contact_no and description and location and timings and file and category:
            try:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                job_id = "J"+str(len(Worker.query.all()))
                job = Worker(name=name,user_id=current_user.id,job_id=job_id,category=category, email=email, job=job, contact_no=contact_no, description=description, location=location, timings=timings, cv=filename)
                db.session.add(job)
                db.session.commit()
            except:
                flash('User/Job already exists', 'error')
            flash('Job uploaded', 'success')
            print('Job uploaded')
            return redirect(url_for('jobs',user=current_user))
        else:
            flash('Please fill in all fields', 'error')
            print('Please fill in all fields')
            return redirect(url_for('jobs'))
        
    return render_template('upload_job.html', user=current_user)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',sender="Flask Mail Service",recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
                    {url_for('reset_token', token=token, _external=True)}
                    '''
    mail.send(msg)
    flash("Reset email sent (check spam folder)", 'success')
    return redirect(url_for('index'))

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
        else:
            flash('Email not found', 'error')
            return redirect(url_for('reset_request'))
    return render_template('reset_request.html', user=current_user)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            if user.reset_password(token, generate_password_hash(password,method="sha256")):
                flash('Password updated', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid token', 'error')
                return redirect(url_for('reset_request'))
        else:
            flash('Email not found', 'error')
            return redirect(url_for('reset_request'))
    return render_template('reset_token.html', user=current_user, token=token)

@app.route('/send-mail', methods=['GET', 'POST'])
def contact_mail():
    username = request.form['username']
    email = request.form['email']
    mobile_no = request.form['mobile_no']
    msg = request.form['msg']
    if username and email and mobile_no and msg:
        message = Message('Contact Us', sender='Flask Mail Service', recipients=[email])
        message.body = f'''
        Name: {username}
        Email: {email}
        Mobile No: {mobile_no}
        Message: {msg}
        '''
        mail.send(message)
        flash('Mail sent', 'success')
        return redirect(url_for('index'))
    else:
        flash('Please fill in all fields', 'error')
        return redirect(url_for('index'))


@app.route('/files/<filename>', methods=['GET', 'POST'])
def view_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/delete/<int:id>')
@login_required
def delete_job(id):
    job = Worker.query.get_or_404(id)
    if job!=None:
        db.session.delete(job)
        db.session.commit()
        if current_user.isAdmin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('jobs',user=current_user))
    else:
        flash('Error', 'error')
    return redirect(url_for('jobs',user=current_user))
        
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    jobs = Worker.query.all()
    if current_user.isAdmin:
        return render_template('workers.html',user=current_user, jobs=jobs)
    else:
        flash('Access denied', 'error')
        return redirect(url_for('admin'))
    return render_template('dashboard.html',user=current_user, jobs=jobs)


# views

@app.route('/')
def index():
    return render_template('index.html', user=current_user)

@app.route('/about')
def about():
    return render_template('about_us.html',user=current_user)

@app.route('/jobs')
def jobs():
    jobs = Worker.query.all()
    list_of_jobs = []
    for job in jobs:
        if job.category not in list_of_jobs:
            list_of_jobs.append(str(job.category).capitalize())

    return render_template('all_jobs.html',user=current_user, jobs=jobs,list_of_jobs=list_of_jobs)
@app.route('/jobs/<category>')
def job_category(category):
    jobs = Worker.query.all()
    list_of_jobs = []
    for job in jobs:
        if job.category not in list_of_jobs:
            list_of_jobs.append(job.category)
    return render_template('categories.html',user=current_user, jobs=jobs, category=category, list_of_jobs=list_of_jobs)




@app.route('/jobs/edit/<int:id>',methods=['GET','POST'])
@login_required
def edit_job(id):
    job = Worker.query.filter_by(id=id).first()
    if job.user_id == current_user.id:
        if request.method == 'POST':
            name = request.form['username']
            category = request.form['category']
            email = request.form['email']
            job = request.form['job']
            contact_no = request.form['contact_no']
            description = request.form['description']
            location = request.form['location']
            timings = request.form['timings']
            file = request.files['filename']
            if name and category and email and job and contact_no and description and location and timings:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # try:
                Worker.query.filter_by(id=id).update(dict(name=name, category=category, email=email, job=job, contact_no=contact_no, description=description, location=location, timings=timings, cv=filename))
                db.session.commit()
                flash('Job updated', 'success')
        
                return redirect(url_for('jobs',user=current_user))
            else:
                flash('Please fill in all fields', 'error')
                return redirect(url_for('jobs'))
        return render_template('edit_job.html',user=current_user, job=job)
    else:
        flash('Access denied', 'error')
        return redirect(url_for('jobs'))

@app.route('/contact')
def contact():
    return render_template('contact_us.html',user=current_user)

@app.route('/services')
def services():
    return render_template('services.html',user=current_user)

@app.route('/gallery')
def gallery():
    return render_template('gallery.html',user=current_user)

# @app.route('/make-admin', methods=['GET', 'POST'])
# def make_admin():
#     if request.method == 'POST':
#         username = request.form['username']
#         email = request.form['email']
#         password = request.form['pass']
#         if username and email and password:
#             admin = Admin(username=username, email=email, password=password)
#             db.session.add(admin)
#             db.session.commit()
#             print('Admin created')
#     return render_template('make_admin.html')


# @app.route('/admin', methods=['GET', 'POST'])
# def admin():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['pass']
#         user = User.query.filter_by(email=email).first()
#         if password==user.password and user.isAdmin:
#             login_user(user,remember=True)
#             return redirect(url_for('admin_dashboard'))
#         else:
#             flash('Invalid credentials', 'error')
#             return redirect(url_for('admin'))
#     return render_template('admin.html', user=current_user)

if "__name__" == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0",port=port,debug=False)