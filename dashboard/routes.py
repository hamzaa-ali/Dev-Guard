from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from shared.models import User


def register_routes(app, login_manager):

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── ROOT ──
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    # ── LOGIN ──
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            user     = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user)
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')

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
        from shared.models import Finding, Scan, PostureScore, Repo
        from pipeline.posture_score import get_score_label

        # Get latest posture score across all repos
        latest_posture = PostureScore.query.order_by(
            PostureScore.created_at.desc()
        ).first()

        current_score = latest_posture.score if latest_posture else None
        score_label, score_class = get_score_label(
            current_score
        ) if current_score is not None else ('No scans yet', 'score-neutral')

        # Count findings by severity
        all_findings = Finding.query.filter(
            Finding.confidence_label != 'Low Confidence'
        ).all()

        critical_count = sum(
            1 for f in all_findings if f.normalized_severity >= 9.0
        )
        high_count = sum(
            1 for f in all_findings
            if 7.0 <= f.normalized_severity < 9.0
        )
        medium_count = sum(
            1 for f in all_findings
            if 4.0 <= f.normalized_severity < 7.0
        )
        low_count = sum(
            1 for f in all_findings if f.normalized_severity < 4.0
        )

        # Total scans
        total_scans = Scan.query.filter_by(status='completed').count()

        # Recent scans for dashboard table
        recent_scans = Scan.query.order_by(
            Scan.started_at.desc()
        ).limit(5).all()

        return render_template(
            'dashboard.html',
            current_score  = current_score,
            score_label    = score_label,
            score_class    = score_class,
            critical_count = critical_count,
            high_count     = high_count,
            medium_count   = medium_count,
            low_count      = low_count,
            total_scans    = total_scans,
            recent_scans   = recent_scans,
        )

    # ── SCANS ──
    @app.route('/scans')
    @login_required
    def scans():
        from shared.models import Scan
        scans = Scan.query.order_by(Scan.started_at.desc()).all()
        return render_template('scans.html', scans=scans)

    # ── FINDINGS ──
    @app.route('/findings')
    @login_required
    def findings():
        from shared.models import Finding
        all_findings = Finding.query.order_by(
            Finding.normalized_severity.desc()
        ).all()
        return render_template('findings.html', findings=all_findings)

    # ── REPOSITORIES ──
    @app.route('/repositories')
    @login_required
    def repositories():
        from shared.models import Repo
        repos = Repo.query.order_by(Repo.created_at.desc()).all()
        return render_template('repositories.html', repos=repos)

    # ── POSTURE SCORE ──
    @app.route('/posture')
    @login_required
    def posture():
        from shared.models import PostureScore, Repo
        from pipeline.posture_score import get_score_label

        # Get all posture scores ordered by date
        all_scores = PostureScore.query.order_by(
            PostureScore.created_at.asc()
        ).all()

        # Build chart data
        chart_labels = [
            s.created_at.strftime('%b %d %H:%M')
            for s in all_scores
        ]
        chart_data = [s.score for s in all_scores]

        # Latest score
        latest = all_scores[-1] if all_scores else None
        current_score = latest.score if latest else None
        score_label, score_class = get_score_label(
            current_score
        ) if current_score is not None else ('No scans yet', 'score-neutral')

        return render_template(
            'posture.html',
            all_scores    = all_scores,
            chart_labels  = chart_labels,
            chart_data    = chart_data,
            current_score = current_score,
            score_label   = score_label,
            score_class   = score_class,
        )

    # ── REPORTS ──
    @app.route('/reports')
    @login_required
    def reports():
        from shared.models import Scan
        scans = Scan.query.filter_by(
            status='completed'
        ).order_by(Scan.started_at.desc()).all()
        return render_template('reports.html', scans=scans)