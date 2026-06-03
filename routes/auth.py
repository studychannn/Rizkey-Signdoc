from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
from models import User
from crypto_utils import generate_rsa_keypair, encrypt_private_key, get_public_key_pem

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def index():
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']

        # Validasi input
        if not username or len(username) < 3:
            flash('Username minimal 3 karakter.', 'error')
            return render_template('register.html')
        if not email or '@' not in email:
            flash('Format email tidak valid.', 'error')
            return render_template('register.html')
        if len(password) < 8:
            flash('Password minimal 8 karakter.', 'error')
            return render_template('register.html')
        if not any(c.isdigit() for c in password):
            flash('Password harus mengandung minimal 1 angka.', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username sudah digunakan.', 'error')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email sudah digunakan.', 'error')
            return render_template('register.html')

        # Generate key pair RSA-2048
        private_key = generate_rsa_keypair()

        encrypted_priv = encrypt_private_key(private_key, password)
        public_key_pem = get_public_key_pem(private_key)

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            public_key=public_key_pem,
            encrypted_private_key=encrypted_priv,
        )
        db.session.add(user)
        db.session.commit()

        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('docs.dashboard'))
        flash('Username atau password salah.', 'error')
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
