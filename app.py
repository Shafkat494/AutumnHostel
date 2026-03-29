from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import os
from functools import wraps
from sqlalchemy import extract, func

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key_change_this')

# ------------------ Database Configuration ------------------S

# Get the absolute path to the current directory
basedir = os.path.abspath(os.path.dirname(__file__))

# Define the instance folder path
instance_path = os.path.join(basedir, 'instance')

# Ensure the folder exists (creates it if missing)
os.makedirs(instance_path, exist_ok=True)

# Default SQLite database path
DEFAULT_SQLITE = f"sqlite:///{os.path.join(instance_path, 'local.db')}"

# Use DATABASE_URL if provided (for deployment), otherwise default to SQLite
database_url = os.environ.get('DATABASE_URL', DEFAULT_SQLITE)

# Fix for MySQL URI format on Render
if database_url.startswith("mysql://"):
    database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)

# SQLAlchemy configuration
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Optional: avoids timeout issues on some hosting platforms
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True
}

# Initialize SQLAlchemy
db = SQLAlchemy(app)

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
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    breakfast = db.Column(db.Boolean, default=False)
    lunch = db.Column(db.Boolean, default=False)
    dinner = db.Column(db.Boolean, default=False)
    supper = db.Column(db.Boolean, default=False)

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

# ------------------ Login Required Decorator ------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


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
        if login_type in ['admin', 'manager']:
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

    return render_template('login.html', login_type=login_type)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ------------------new changes-------------------

@app.route('/admin_signup', methods=['GET','POST'])
def admin_signup():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
        admin_key = request.form['admin_key']

        # 🔐 YOUR SECRET KEY
        SECRET_KEY = "longing"

        if admin_key != SECRET_KEY:
            flash("Invalid Admin Key!", "danger")
            return redirect(url_for('admin_signup'))

        # Create admin
        user = User(username=username, role='admin')
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash("Admin account created successfully!", "success")
        return redirect(url_for('login'))

    return render_template('admin_signup.html')

# ----------------- manager creation (new change) ------------------

@app.route('/create_manager', methods=['GET', 'POST'])
@role_required('admin')
def create_manager():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']

        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('create_manager'))

        # Create manager
        manager = User(
            username=username,
            role='manager',
            full_name=full_name
        )
        manager.set_password(password)

        db.session.add(manager)
        db.session.commit()

        flash("Manager created successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('create_manager.html')
 
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

@app.route('/clear_day', methods=['POST'])
@role_required('admin', 'manager')
def clear_day():
    session.pop('selected_day', None)
    flash("Day selection cleared. You can choose a new day.", "info")
    return redirect(url_for('menu'))

# ------------------ Menu Management ------------------

@app.route('/menu', methods=['GET', 'POST'])
@role_required('admin', 'manager')
def menu():
    if request.method == 'POST':
        # Get selected day
        day = request.form.get('day')
        if not day:
            flash("Please select a day.", "warning")
            return redirect(url_for('menu'))

        # Store the selected day in session for convenience
        session['selected_day'] = day

        # Iterate over the four meals
        for meal in ['breakfast', 'lunch', 'dinner', 'supper']:
            items_text = request.form.get(f'meal_{meal}', '').strip()
            if items_text:
                # Split multiple items by comma
                items_list = [i.strip() for i in items_text.split(',') if i.strip()]
                for item in items_list:
                    new_menu = Menu(day=day, meal=meal.capitalize(), item=item)
                    db.session.add(new_menu)

        db.session.commit()
        flash(f"Menu saved for {day}.", "success")
        return redirect(url_for('menu'))

    # GET request: show all menu items
    all_items = Menu.query.order_by(Menu.day, Menu.meal).all()
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
    meal_type = request.args.get('meal', 'dinner')  # default meal = dinner

    if request.method == 'POST':
        present_ids = request.form.getlist('present')

        for student in all_students:
            if str(student.id) in present_ids:
                existing = Attendance.query.filter_by(student_id=student.id, date=today, meal=meal_type).first()
                if not existing:
                    new_att = Attendance(student_id=student.id, date=today, meal=meal_type)
                    db.session.add(new_att)

                    # Dinner auto-marks breakfast
                    if meal_type == 'dinner':
                        breakfast_check = Attendance.query.filter_by(student_id=student.id, date=today, meal='breakfast').first()
                        if not breakfast_check:
                            db.session.add(Attendance(student_id=student.id, date=today, meal='breakfast'))

        db.session.commit()
        flash(f"{meal_type.capitalize()} attendance marked successfully ✅", "success")
        return redirect(url_for('attendance', meal=meal_type))

    return render_template('attendance.html', students=all_students, today=today, meal_type=meal_type)

# ------------------ Student Attendance ------------------

@app.route('/student/attendance', methods=['GET', 'POST'])
@login_required
def student_attendance():
    student = Student.query.get(session['user_id'])
    today = date.today()

    if not student:
        flash("Student not found.", "danger")
        return redirect(url_for('logout'))

    if request.method == 'POST':
        # Get all selected meals (checkboxes)
        meals = request.form.getlist('meal')

        if not meals:
            flash("Please select at least one meal.", "warning")
            return redirect(url_for('student_attendance'))

        # Find or create today's attendance record
        attendance = Attendance.query.filter_by(student_id=student.id, date=today).first()

        if not attendance:
            attendance = Attendance(student_id=student.id, date=today)
            db.session.add(attendance)

        # Mark selected meals
        for meal in meals:

            # Skip if already marked
            if getattr(attendance, meal):
                continue

            setattr(attendance, meal, True)

            # Existing logic preserved
            if meal == 'dinner':
                attendance.breakfast = True

            if meal == 'supper':
                attendance.dinner = True
                attendance.breakfast = True

        db.session.commit()

        # Correct flash message
        if len(meals) == 4:
            flash("Attendance marked for today for all meals.", "success")
        else:
            meal_names = ", ".join([m.capitalize() for m in meals])
            flash(f"Attendance marked for {meal_names}.", "success")

        return redirect(url_for('student_attendance'))

    return render_template(
        'student_attendance.html',
        student=student,
        today=today
    )

@app.route('/attendance_summary/<selected_date>')
@role_required('admin', 'manager')
def attendance_summary(selected_date):
    # Convert string to date object
    try:
        selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d').date()
    except ValueError:
        flash("Invalid date format.", "danger")
        return redirect(url_for('attendance_report'))

    import calendar
    from sqlalchemy import extract, func

    # Month/year for summary
    month = selected_date_obj.month
    year = selected_date_obj.year

    total_days_in_month = calendar.monthrange(year, month)[1]

    # Query monthly attendance
    monthly_query = (
        db.session.query(
            Student.id.label('student_id'),
            Student.name.label('name'),
            func.count(Attendance.id).label('days_present')
        )
        .join(Attendance, Attendance.student_id == Student.id)
        .filter(
            extract('year', Attendance.date) == year,
            extract('month', Attendance.date) == month
        )
        .group_by(Student.id)
        .all()
    )

    # Prepare dictionary for all students
    monthly_attendance = {}
    for s in Student.query.all():
        monthly_attendance[s.id] = {
            'name': s.name,
            'days_present': 0,
            'total_days_in_month': total_days_in_month,
            'absent_days': total_days_in_month,
            'attendance_pct': 0.0
        }

    for row in monthly_query:
        sid = row.student_id
        days = int(row.days_present or 0)
        monthly_attendance[sid]['days_present'] = days
        monthly_attendance[sid]['absent_days'] = max(0, total_days_in_month - days)
        if total_days_in_month > 0:
            monthly_attendance[sid]['attendance_pct'] = round((days / total_days_in_month) * 100, 1)

    return render_template(
        'attendance_summary.html',
        selected_date=selected_date_obj,
        monthly_attendance=monthly_attendance,
        total_days_in_month=total_days_in_month
    )

# ------------------ Student Menu ------------------

@app.route('/student_menu')
@role_required('student')
def student_menu():
    weekday = date.today().strftime('%A')
    todays_menu = Menu.query.filter_by(day=weekday).all()
    return render_template('student_menu.html', menu_items=todays_menu, weekday=weekday)

# ------------------ Attendance report ------------------

@app.route('/attendance_report', methods=['GET', 'POST'])
@role_required('admin', 'manager')
def attendance_report():
    # Step 1: Read selected date from the form or query
    date_str = request.values.get('selected_date')
    
    if date_str:
        try:
            selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            selected_date = date.today()
    else:
        selected_date = date.today()

    meal_type = request.args.get('meal', 'dinner')

    # Read selected meal from query string or default to dinner
    meal_type = request.args.get('meal', 'dinner')

    # Step 2: Get present students for that selected date
    present_students = (
        db.session.query(Student)
        .join(Attendance)
        .filter(
            Attendance.date == selected_date,
            getattr(Attendance, meal_type) == True
        )
        .all()
    )

    # Step 3: Count total and present students
    total_students = Student.query.count()
    present_count = len(present_students)

    # ----------------- APPENDED: Monthly attendance logic -----------------
    # (uses SQL functions locally so we don't need to change top-level imports)
    from sqlalchemy import extract, func
    import calendar

    month = selected_date.month
    year = selected_date.year

    # Actual number of days in the selected month
    total_days_in_month = calendar.monthrange(year, month)[1]

    # Query: count attendance rows per student in the selected month
    monthly_query = (
        db.session.query(
            Student.id.label('student_id'),
            Student.name.label('name'),
            func.count(Attendance.id).label('days_present')
        )
        .join(Attendance, Attendance.student_id == Student.id)
        .filter(
            extract('year', Attendance.date) == year,
            extract('month', Attendance.date) == month
        )
        .group_by(Student.id)
        .all()
    )

    # Prepare dictionary mapping student_id -> info (ensure all students included)
    monthly_attendance = {}
    # initialize 0 for all students
    for s in Student.query.all():
        monthly_attendance[s.id] = {
            'name': s.name,
            'days_present': 0,
            'total_days_in_month': total_days_in_month,
            'absent_days': total_days_in_month,   # will adjust below
            'attendance_pct': 0.0
        }

    # fill counts from query results
    for row in monthly_query:
        sid = row.student_id
        days = int(row.days_present or 0)
        monthly_attendance[sid]['days_present'] = days
        monthly_attendance[sid]['absent_days'] = max(0, total_days_in_month - days)
        if total_days_in_month > 0:
            monthly_attendance[sid]['attendance_pct'] = round((days / total_days_in_month) * 100, 1)
        else:
            monthly_attendance[sid]['attendance_pct'] = 0.0

    # ----------------------------------------------------------------------

    # Step 4: Render the page (keeps original variable 'today' referencing selected_date)
    return render_template(
        'attendance_report.html',
        today=selected_date,               # use the selected date (keeps existing template usage)
        present_students=present_students,
        total_students=total_students,
        present_count=present_count,
        selected_date=selected_date,       # for form display (keeps earlier behavior)
        monthly_attendance=monthly_attendance,
        total_days_in_month=total_days_in_month,
        meal_type=meal_type
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

        new_feedback = Feedback(
            student_id=student.id,
            message=message,
            rating=rating
        )

        db.session.add(new_feedback)
        db.session.commit()

        flash("Thank you for your feedback! ✅", "success")

        # IMPORTANT: stay on feedback page
        return redirect(url_for('student_feedback'))

    # Get previous feedbacks of THIS student
    feedbacks = Feedback.query.filter_by(student_id=student.id)\
                              .order_by(Feedback.created_at.desc())\
                              .limit(3)\
                              .all()

    return render_template(
        'student_feedback.html',
        student=student,
        feedbacks=feedbacks
    )

@app.route('/admin_feedbacks')
@role_required('admin', 'manager')
def admin_feedbacks():
    all_feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).all()
    return render_template('admin_feedbacks.html', feedbacks=all_feedbacks)

# ------------------ Delete Feedback -------------------

@app.route('/delete_feedback/<int:feedback_id>', methods=['POST'])
@role_required('student')
def delete_feedback(feedback_id):

    student = Student.query.get(session['user_id'])
    feedback = Feedback.query.get(feedback_id)

    if not feedback or feedback.student_id != student.id:
        flash("You cannot delete this feedback.", "danger")
        return redirect(url_for('student_feedback'))

    db.session.delete(feedback)
    db.session.commit()

    flash("Feedback deleted successfully.", "success")

    return redirect(url_for('student_feedback'))

# ------------------ Run App ------------------

if __name__ == "__main__":
    # This allows local testing
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

