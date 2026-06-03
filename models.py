from extensions import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    signatures = db.relationship('Signature', backref='signer', lazy=True)
    sent_invitations = db.relationship('Invitation', foreign_keys='Invitation.inviter_id', backref='inviter', lazy=True)
    received_invitations = db.relationship('Invitation', foreign_keys='Invitation.invitee_id', backref='invitee', lazy=True)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    qr_code_path = db.Column(db.String(256))

    uploader = db.relationship('User', foreign_keys=[uploaded_by])
    signatures = db.relationship('Signature', backref='document', lazy=True)
    invitations = db.relationship('Invitation', backref='document', lazy=True)

class Signature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    signature_data = db.Column(db.Text, nullable=False)  # base64 encoded RSA-PSS signature
    signed_at = db.Column(db.DateTime, default=datetime.utcnow)
    doc_hash_at_signing = db.Column(db.String(64), nullable=False)

class Invitation(db.Model):
    """Undangan untuk menandatangani dokumen."""
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)   # yang mengundang
    invitee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)   # yang diundang
    status = db.Column(db.String(20), default='pending')  # pending | signed | declined
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        db.UniqueConstraint('document_id', 'invitee_id', name='uq_doc_invitee'),
    )
