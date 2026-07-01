from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime

# These two objects will be attached to your Flask app later
db = SQLAlchemy()
bcrypt = Bcrypt()


# ─────────────────────────────────────────
# TABLE 1: users
# Stores dashboard login accounts
# ─────────────────────────────────────────
class User(db.Model):
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, plain_password):
        self.password_hash = bcrypt.generate_password_hash(plain_password).decode('utf-8')

    def check_password(self, plain_password):
        return bcrypt.check_password_hash(self.password_hash, plain_password)

    def __repr__(self):
        return f'<User {self.username}>'


# ─────────────────────────────────────────
# TABLE 2: repos
# Stores each GitHub repository DevGuard monitors
# ─────────────────────────────────────────
class Repo(db.Model):
    __tablename__ = 'repos'

    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(200), nullable=False)
    github_url = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Links to other tables
    config         = db.relationship('RepoConfig', backref='repo', uselist=False)
    scans          = db.relationship('Scan', backref='repo', lazy=True)
    posture_scores = db.relationship('PostureScore', backref='repo', lazy=True)

    def __repr__(self):
        return f'<Repo {self.name}>'


# ─────────────────────────────────────────
# TABLE 3: repo_configs
# Stores which scanners are on/off per repo
# ─────────────────────────────────────────
class RepoConfig(db.Model):
    __tablename__ = 'repo_configs'

    id                  = db.Column(db.Integer, primary_key=True)
    repo_id             = db.Column(db.Integer, db.ForeignKey('repos.id'), nullable=False)
    run_semgrep         = db.Column(db.Boolean, default=True)
    run_trivy           = db.Column(db.Boolean, default=True)
    run_gitleaks        = db.Column(db.Boolean, default=True)
    severity_threshold  = db.Column(db.Float, default=0.0)  # minimum severity to store
    updated_at          = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<RepoConfig repo_id={self.repo_id}>'


# ─────────────────────────────────────────
# TABLE 4: scans
# One row per scan triggered by a git push
# ─────────────────────────────────────────
class Scan(db.Model):
    __tablename__ = 'scans'

    id           = db.Column(db.Integer, primary_key=True)
    repo_id      = db.Column(db.Integer, db.ForeignKey('repos.id'), nullable=False)
    commit_hash  = db.Column(db.String(40), nullable=True)
    status       = db.Column(db.String(20), default='pending')
    # status values: pending / running / completed / failed
    started_at   = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Links to other tables
    findings      = db.relationship('Finding', backref='scan', lazy=True)
    posture_score = db.relationship('PostureScore', backref='scan', uselist=False)

    def __repr__(self):
        return f'<Scan id={self.id} status={self.status}>'


# ─────────────────────────────────────────
# TABLE 5: findings
# Every vulnerability found goes here
# ─────────────────────────────────────────
class Finding(db.Model):
    __tablename__ = 'findings'

    id                  = db.Column(db.Integer, primary_key=True)
    scan_id             = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    tool                = db.Column(db.String(20), nullable=False)
    # tool values: semgrep / trivy / gitleaks
    rule_id             = db.Column(db.String(200), nullable=True)
    file_path           = db.Column(db.String(500), nullable=True)
    line_number         = db.Column(db.Integer, nullable=True)
    message             = db.Column(db.Text, nullable=False)
    raw_severity        = db.Column(db.String(50), nullable=True)
    # raw_severity: the original label from the tool e.g. "ERROR", "HIGH", "CRITICAL"
    normalized_severity = db.Column(db.Float, nullable=True)
    # normalized_severity: your 0-10 score after mapping
    confidence_label    = db.Column(db.String(20), nullable=True)
    # confidence_label values: Confirmed / Review Needed / Low Confidence
    confidence_score    = db.Column(db.Float, nullable=True)
    # confidence_score: 1-10 number from your heuristic filter
    created_at          = db.Column(db.DateTime, default=datetime.utcnow)

    # Links to other tables
    ai_analysis = db.relationship('AIAnalysis', backref='finding', uselist=False)

    def __repr__(self):
        return f'<Finding tool={self.tool} severity={self.normalized_severity}>'


# ─────────────────────────────────────────
# TABLE 6: ai_analyses
# Stores the AI explanation for each finding
# ─────────────────────────────────────────
class AIAnalysis(db.Model):
    __tablename__ = 'ai_analyses'

    id            = db.Column(db.Integer, primary_key=True)
    finding_id    = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=False)
    root_cause    = db.Column(db.Text, nullable=True)
    attack_impact = db.Column(db.Text, nullable=True)
    fixed_code    = db.Column(db.Text, nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<AIAnalysis finding_id={self.finding_id}>'


# ─────────────────────────────────────────
# TABLE 7: posture_scores
# Stores the 0-10 security health score per scan
# ─────────────────────────────────────────
class PostureScore(db.Model):
    __tablename__ = 'posture_scores'

    id             = db.Column(db.Integer, primary_key=True)
    scan_id        = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    repo_id        = db.Column(db.Integer, db.ForeignKey('repos.id'), nullable=False)
    score          = db.Column(db.Float, nullable=False)
    previous_score = db.Column(db.Float, nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<PostureScore score={self.score}>'