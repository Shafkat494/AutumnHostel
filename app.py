from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key_change_this')

# ------------------ Database Configuration ------------------

DEFAULT_SQLITE = 'sqlite:///local.db'
database_url = os.environ.get('DATABASE_URL', DEFAULT_SQLITE)

# Fix for MySQL URI format on Render
if database_url.startswith("mysql://"):
    database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Optional: avoids timeout issues on Render
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True
}

db = SQLAlchemy(app)
# ------------------------------------------------------------


# ------------------ Database Models ------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'manager'
    full_name = db.Column(db.String(100))

    def set_password(self, raw_password):
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password, raw_password)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))
    room = db.Column(db.String(10))
    allergies = db.Column(db.String(100))
    food_type = db.Column(db.String(20))  # veg/non-veg
    days_present = db.Column(db.Integer, default=0)

    def set_password(self, raw_password):
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        if not self.password:
            return False
        return check_password_hash(self.password, raw_password)

class Menu(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(10), nullable=False)
    meal = db.Column(db.String(50), nullable=False)
    item = db.Column(db.String(100), nullable=False)
    food_type = db.Column(db.String(20))

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='CASCADE'), nullable=False)
    date = db.Column(db.Date, nullable=False)

class AllergyReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='CASCADE'), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey('menu.id', ondelete='CASCADE'), nullable=False)
    allergy_text = db.Column(db.String(200))
    date = db.Column(db.Date, nullable=False, default=date.today)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='SET NULL'))
    message = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer)
    created_at = db.Column(db.Date, default=date.today)


# ------------------ Initialize DB & Default Users ------------------

with app.app_context():
    db.create_all()

    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin', full_name='Administrator')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

    if not User.query.filter_by(username='manager').first():
        manager = User(username='manager', role='manager', full_name='Food Manager')
        manager.set_password('manager123')
        db.session.add(manager)
        db.session.commit()

# ------------------ Role Decorator ------------------

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ------------------ Routes ------------------

@app.route('/')
def home():
    if 'role' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session['role'] == 'manager':
            return redirect(url_for('manager_dashboard'))
        elif session['role'] == 'student':
            return redirect(url_for('student_dashboard'))
    return render_template('index.html')


# ------------------ Authentication ------------------



@app.route('/login', methods=['GET', 'POST'])
def login():
    # Determine requested login type from querystring (GET) or from the form (POST)
    login_type = request.args.get('login_type', 'admin_manager')

    # If POST, prefer the form value (keeps login_type through the submit)
    if request.method == 'POST':
        login_type = request.form.get('login_type', login_type)
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # --- Admin / Manager login (shared page) ---
        if login_type == 'admin_manager':
            user = User.query.filter_by(username=username).first()
            if user and user.role in ['admin', 'manager'] and user.check_password(password):
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                # Redirect to the right dashboard
                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('manager_dashboard'))
            else:
                flash('Invalid Admin/Manager credentials!', 'danger')

        # --- Student login ---
        elif login_type == 'student':
            student = Student.query.filter_by(username=username).first()
            if student and student.check_password(password):
                session['user_id'] = student.id
                session['username'] = student.username
                session['role'] = 'student'
                return redirect(url_for('student_dashboard'))
            else:
                flash('Invalid Student credentials!', 'danger')

    # GET request: render appropriate login form
    # NOTE: We render the login page even if a session exists,
    # because you may want to allow logout and re-login as another role.
    # If you want to force previously logged-in users to the dashboard, you can add a redirect here.
    return render_template('login.html', login_type=login_type)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ------------------ Dashboards ------------------

@app.route('/admin_dashboard')
@role_required('admin')
def admin_dashboard():
    students_count = Student.query.count()
    menu_count = Menu.query.count()
    today_count = Attendance.query.filter_by(date=date.today()).count()
    return render_template('admin_dashboard.html', students=students_count, menu_items=menu_count, food_count=today_count)

@app.route('/manager_dashboard')
@role_required('manager')
def manager_dashboard():
    students_count = Student.query.count()
    menu_count = Menu.query.count()
    today_count = Attendance.query.filter_by(date=date.today()).count()
    return render_template('manager_dashboard.html', students=students_count, menu_items=menu_count, food_count=today_count)

@app.route('/student_dashboard')
@role_required('student')
def student_dashboard():
    return render_template('student_dashboard.html')

# ------------------ Student Management ------------------

@app.route('/students', methods=['GET', 'POST'])
@role_required('admin', 'manager')
def students():
    if request.method == 'POST':
        name = request.form['name']
        room = request.form['room']
        allergies = request.form['allergies']
        food_type = request.form['food_type']
        username = request.form.get('username')
        password = request.form.get('password')

        new_student = Student(name=name, room=room, allergies=allergies, food_type=food_type, username=username)
        if password:
            new_student.set_password(password)
        db.session.add(new_student)
        db.session.commit()
        return redirect(url_for('students'))

    all_students = Student.query.all()
    return render_template('students.html', students=all_students)

@app.route('/delete_student/<int:student_id>', methods=['POST'])
@role_required('admin', 'manager')
def delete_student(student_id):
    student = Student.query.get(student_id)
    if student:
        db.session.delete(student)
        db.session.commit()
        flash("Student deleted successfully!", "success")
    else:
        flash("Student not found.", "danger")
    return redirect(url_for('students'))

# ------------------ Menu Management ------------------

@app.route('/menu', methods=['GET', 'POST'])
@role_required('admin', 'manager')
def menu():
    if request.method == 'POST':
        day = request.form['day']
        meal = request.form['meal']
        item = request.form['item']
        food_type = request.form['food_type']

        new_item = Menu(day=day, meal=meal, item=item, food_type=food_type)
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for('menu'))

    all_items = Menu.query.all()
    return render_template('menu.html', menus=all_items)

@app.route('/menu/delete/<int:item_id>', methods=['POST'])
@role_required('admin', 'manager')
def delete_menu(item_id):
    item = Menu.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('menu'))

# ------------------ Attendance ------------------

@app.route('/attendance', methods=['GET', 'POST'])
@role_required('admin', 'manager')
def attendance():
    all_students = Student.query.all()
    today = date.today()

    if request.method == 'POST':
        present_ids = request.form.getlist('present')
        for student in all_students:
            if str(student.id) in present_ids:
                existing = Attendance.query.filter_by(student_id=student.id, date=today).first()
                if not existing:
                    new_att = Attendance(student_id=student.id, date=today)
                    db.session.add(new_att)
                    student.days_present += 1
        db.session.commit()
        return redirect(url_for('attendance'))

    return render_template('attendance.html', students=all_students, today=today)

@app.route('/student_attendance', methods=['GET', 'POST'])
@role_required('student')
def student_attendance():
    student = Student.query.filter_by(username=session['username']).first()
    if not student:
        flash("Student record not found.", "danger")
        return redirect(url_for('logout'))

    today = date.today()  # current date

    if request.method == 'POST':
        existing = Attendance.query.filter_by(student_id=student.id, date=today).first()
        if not existing:
            new_att = Attendance(student_id=student.id, date=today)
            db.session.add(new_att)
            student.days_present += 1
            db.session.commit()
            flash("Attendance marked successfully! ✅", "success")
        else:
            flash("Attendance already marked for today!", "warning")
        return redirect(url_for('student_attendance'))

    # Pass 'today' to the template so Jinja2 can render it
    return render_template('student_attendance.html', student=student, today=today)

# ------------------ Student Menu ------------------

@app.route('/student_menu')
@role_required('student')
def student_menu():
    weekday = date.today().strftime('%A')
    todays_menu = Menu.query.filter_by(day=weekday).all()
    return render_template('student_menu.html', menu_items=todays_menu, weekday=weekday)

# ------------------ Food Count ------------------

@app.route('/food_count')
@role_required('admin', 'manager')
def food_count():
    today = date.today()
    weekday = today.strftime('%A')

    present_students = db.session.query(Student).join(Attendance).filter(Attendance.date == today).all()
    todays_menu = Menu.query.filter_by(day=weekday).all()

    veg_count = 0
    nonveg_count = 0
    allergy_issues = []

    for student in present_students:
        if student.food_type and student.food_type.lower() == 'veg':
            veg_count += 1
        else:
            nonveg_count += 1

        for item in todays_menu:
            if student.allergies and student.allergies.lower() in item.item.lower():
                allergy_issues.append({'student': student.name, 'item': item.item})

    return render_template(
        'food_count.html',
        veg_count=veg_count,
        nonveg_count=nonveg_count,
        allergy_issues=allergy_issues,
        todays_menu=todays_menu,
        weekday=weekday
    )


# ------------------ Feedback ------------------

@app.route('/student_feedback', methods=['GET', 'POST'])
@role_required('student')
def student_feedback():
    student = Student.query.filter_by(username=session['username']).first()
    if not student:
        flash("Student record not found.", "danger")
        return redirect(url_for('logout'))

    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        rating = request.form.get('rating', None)

        if not message:
            flash("Please enter your feedback before submitting.", "warning")
            return redirect(url_for('student_feedback'))

        new_feedback = Feedback(student_id=student.id, message=message, rating=rating)
        db.session.add(new_feedback)
        db.session.commit()

        flash("Thank you for your feedback! ✅", "success")
        return redirect(url_for('student_dashboard'))

    return render_template('student_feedback.html')

@app.route('/admin_feedbacks')
@role_required('admin', 'manager')
def admin_feedbacks():
    all_feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).all()
    return render_template('admin_feedbacks.html', feedbacks=all_feedbacks)

# ------------------ Run App ------------------

if __name__ == "__main__":
    # This allows local testing
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

