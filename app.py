from flask import Flask
from extensions import db, login_manager
from models import User
import os

def create_app():
    app = Flask(__name__)

    # Load .env sebelum konfigurasi lain
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip())

    # SECRET_KEY dari .env — persisten antar restart
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        raise RuntimeError("SECRET_KEY tidak ditemukan di .env! Tambahkan SECRET_KEY=<nilai> ke file .env")
    app.config['SECRET_KEY'] = secret_key

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///signdoc.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = 'uploads'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('static/qrcodes', exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from routes.auth import auth_bp
    from routes.documents import docs_bp
    from routes.verify import verify_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(docs_bp)
    app.register_blueprint(verify_bp)

    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
