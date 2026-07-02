from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from shared.models import User


def register_routes(app, login_manager):

    # Tells Flask-Login how to find a user by their ID
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── ROOT → redirect to login or dashboard ──
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    # ── LOGIN ──
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # If already logged in, go straight to dashboard
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user)
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password. Please try again.', 'error')

        return render_template('login.html')

    # ── LOGOUT ──
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('login'))

    # ── MAIN DASHBOARD ──
    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html')

    # ── SCANS ──
    @app.route('/scans')
    @login_required
    def scans():
        return render_template('scans.html')

    # ── FINDINGS ──
    @app.route('/findings')
    @login_required
    def findings():
        return render_template('findings.html')

    # ── REPOSITORIES ──
    @app.route('/repositories')
    @login_required
    def repositories():
        return render_template('repositories.html')

    # ── POSTURE SCORE ──
    @app.route('/posture')
    @login_required
    def posture():
        return render_template('posture.html')

    # ── REPORTS ──
    @app.route('/reports')
    @login_required
    def reports():
        return render_template('reports.html')