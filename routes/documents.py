from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from extensions import db
from models import Document, Signature, User, Invitation
from crypto_utils import hash_file, sign_document, decrypt_private_key, verify_signature
import os, qrcode, io
from datetime import datetime

docs_bp = Blueprint('docs', __name__)

ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx', 'png', 'jpg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_qr(doc_id, base_url):
    verify_url = f"{base_url}/verify/qr/{doc_id}"
    qr = qrcode.make(verify_url)
    path = f"static/qrcodes/doc_{doc_id}.png"
    qr.save(path)
    return path


# ── Dashboard ────────────────────────────────────────────────────────────────

@docs_bp.route('/dashboard')
@login_required
def dashboard():
    my_docs = Document.query.filter_by(uploaded_by=current_user.id).order_by(Document.uploaded_at.desc()).all()

    # Dokumen yang sudah saya tandatangani
    signed_ids = [s.document_id for s in Signature.query.filter_by(user_id=current_user.id).all()]
    signed_docs = Document.query.filter(Document.id.in_(signed_ids)).all() if signed_ids else []

    # Undangan yang belum ditandatangani (pending)
    pending_invitations = (
        Invitation.query
        .filter_by(invitee_id=current_user.id, status='pending')
        .order_by(Invitation.created_at.desc())
        .all()
    )

    return render_template('dashboard.html',
                           my_docs=my_docs,
                           signed_docs=signed_docs,
                           pending_invitations=pending_invitations)


# ── Upload ───────────────────────────────────────────────────────────────────

@docs_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'document' not in request.files:
            flash('Tidak ada file yang dipilih.', 'error')
            return redirect(request.url)
        file = request.files['document']
        if file.filename == '' or not allowed_file(file.filename):
            flash('File tidak valid.', 'error')
            return redirect(request.url)

        file_bytes = file.read()
        file_hash = hash_file(file_bytes)
        filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'wb') as f:
            f.write(file_bytes)

        doc = Document(
            filename=filename,
            original_filename=file.filename,
            file_hash=file_hash,
            uploaded_by=current_user.id
        )
        db.session.add(doc)
        db.session.commit()

        # Generate QR — gunakan IP LAN jika diakses via localhost
        host = request.host
        if host.startswith('127.0.0.1') or host.startswith('localhost'):
            import socket
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
                port = host.split(':')[1] if ':' in host else '5000'
                host = f"{local_ip}:{port}"
            except Exception:
                pass
        base_url = f"{request.scheme}://{host}"
        qr_path = generate_qr(doc.id, base_url)
        doc.qr_code_path = qr_path
        db.session.commit()

        flash(f'Dokumen berhasil diunggah. Hash SHA-256: {file_hash[:16]}...', 'success')
        return redirect(url_for('docs.document_detail', doc_id=doc.id))

    return render_template('upload.html')


# ── Document Detail ──────────────────────────────────────────────────────────

@docs_bp.route('/document/<int:doc_id>')
@login_required
def document_detail(doc_id):
    doc = Document.query.get_or_404(doc_id)
    signatures = Signature.query.filter_by(document_id=doc_id).all()
    already_signed = any(s.user_id == current_user.id for s in signatures)

    # Cek apakah current user punya undangan pending untuk dokumen ini
    my_invitation = Invitation.query.filter_by(
        document_id=doc_id,
        invitee_id=current_user.id,
        status='pending'
    ).first()

    # Daftar undangan yang sudah dikirim untuk dokumen ini
    sent_invitations = Invitation.query.filter_by(document_id=doc_id).all()

    # Cek integritas file
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], doc.filename)
    current_hash = None
    modified = False
    if os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            current_hash = hash_file(f.read())
        if current_hash != doc.file_hash:
            modified = True

    # Apakah current user adalah pemilik dokumen?
    is_owner = (doc.uploaded_by == current_user.id)

    return render_template('document_detail.html',
                           doc=doc,
                           signatures=signatures,
                           already_signed=already_signed,
                           modified=modified,
                           current_hash=current_hash,
                           is_owner=is_owner,
                           my_invitation=my_invitation,
                           sent_invitations=sent_invitations)


# ── Sign Document ────────────────────────────────────────────────────────────

@docs_bp.route('/sign/<int:doc_id>', methods=['POST'])
@login_required
def sign_doc(doc_id):
    doc = Document.query.get_or_404(doc_id)
    password = request.form.get('password')

    if not password:
        flash('Password diperlukan untuk mendekripsi kunci privat.', 'error')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    # Hanya pemilik atau yang diundang yang boleh menandatangani
    is_owner = (doc.uploaded_by == current_user.id)
    invitation = Invitation.query.filter_by(
        document_id=doc_id,
        invitee_id=current_user.id,
        status='pending'
    ).first()

    if not is_owner and not invitation:
        flash('Anda tidak memiliki izin untuk menandatangani dokumen ini.', 'error')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    already_signed = Signature.query.filter_by(document_id=doc_id, user_id=current_user.id).first()
    if already_signed:
        flash('Anda sudah menandatangani dokumen ini.', 'warning')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    try:
        private_key = decrypt_private_key(current_user.encrypted_private_key, password)
    except Exception:
        flash('Password salah atau kunci privat rusak.', 'error')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    sig_data = sign_document(private_key, doc.file_hash)

    last_sig = Signature.query.order_by(Signature.id.desc()).first()
    next_id = max(1000, (last_sig.id + 1) if last_sig else 1000)

    sig = Signature(
        id=next_id,
        document_id=doc_id,
        user_id=current_user.id,
        signature_data=sig_data,
        doc_hash_at_signing=doc.file_hash
    )
    db.session.add(sig)

    # Update status undangan jika ada
    if invitation:
        invitation.status = 'signed'
        invitation.responded_at = datetime.utcnow()

    db.session.commit()
    flash('Dokumen berhasil ditandatangani!', 'success')
    return redirect(url_for('docs.document_detail', doc_id=doc_id))


# ── Invite Signer ────────────────────────────────────────────────────────────

@docs_bp.route('/invite/<int:doc_id>', methods=['POST'])
@login_required
def invite_signer(doc_id):
    doc = Document.query.get_or_404(doc_id)

    # Hanya pemilik dokumen yang bisa mengundang
    if doc.uploaded_by != current_user.id:
        flash('Hanya pemilik dokumen yang dapat mengundang penandatangan.', 'error')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    username = request.form.get('username', '').strip()
    if not username:
        flash('Username tidak boleh kosong.', 'error')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    # Cari user target
    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        flash(f'Pengguna "{username}" tidak ditemukan.', 'error')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    if target_user.id == current_user.id:
        flash('Anda tidak dapat mengundang diri sendiri.', 'error')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    # Cek apakah sudah diundang sebelumnya
    existing = Invitation.query.filter_by(document_id=doc_id, invitee_id=target_user.id).first()
    if existing:
        flash(f'{username} sudah pernah diundang untuk dokumen ini.', 'warning')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    # Cek apakah sudah menandatangani
    already_signed = Signature.query.filter_by(document_id=doc_id, user_id=target_user.id).first()
    if already_signed:
        flash(f'{username} sudah menandatangani dokumen ini.', 'warning')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    invitation = Invitation(
        document_id=doc_id,
        inviter_id=current_user.id,
        invitee_id=target_user.id,
        status='pending'
    )
    db.session.add(invitation)
    db.session.commit()

    flash(f'Undangan berhasil dikirim ke {username}.', 'success')
    return redirect(url_for('docs.document_detail', doc_id=doc_id))


# ── Decline Invitation ───────────────────────────────────────────────────────

@docs_bp.route('/decline/<int:invitation_id>', methods=['POST'])
@login_required
def decline_invitation(invitation_id):
    inv = Invitation.query.get_or_404(invitation_id)
    if inv.invitee_id != current_user.id:
        flash('Aksi tidak diizinkan.', 'error')
        return redirect(url_for('docs.dashboard'))

    inv.status = 'declined'
    inv.responded_at = datetime.utcnow()
    db.session.commit()
    flash('Undangan ditolak.', 'info')
    return redirect(url_for('docs.dashboard'))


# ── Regenerate QR Code ───────────────────────────────────────────────────────

@docs_bp.route('/regenerate-qr/<int:doc_id>', methods=['POST'])
@login_required
def regenerate_qr(doc_id):
    doc = Document.query.get_or_404(doc_id)

    # Hanya pemilik yang bisa regenerate QR
    if doc.uploaded_by != current_user.id:
        flash('Hanya pemilik dokumen yang dapat memperbarui QR code.', 'error')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    host = request.host
    if host.startswith('127.0.0.1') or host.startswith('localhost'):
        import socket
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            port = host.split(':')[1] if ':' in host else '5000'
            host = f"{local_ip}:{port}"
        except Exception:
            pass
    base_url = f"{request.scheme}://{host}"

    qr_path = generate_qr(doc.id, base_url)
    doc.qr_code_path = qr_path
    db.session.commit()

    flash(f'QR Code berhasil diperbarui dengan IP: {host}', 'success')
    return redirect(url_for('docs.document_detail', doc_id=doc_id))


# ── History ──────────────────────────────────────────────────────────────────

@docs_bp.route('/history')
@login_required
def history():
    signatures = Signature.query.filter_by(user_id=current_user.id).order_by(Signature.signed_at.desc()).all()
    return render_template('history.html', signatures=signatures)


# ── Download Signature File (.sig) ───────────────────────────────────────────

@docs_bp.route('/download/signature/<int:sig_id>')
@login_required
def download_signature_file(sig_id):
    sig = Signature.query.get_or_404(sig_id)
    buf = io.BytesIO(sig.signature_data.encode())
    return send_file(buf, as_attachment=True,
                     download_name=f"signature_{sig_id}.sig",
                     mimetype='text/plain')


# ── Download Public Key (.pem) ───────────────────────────────────────────────

@docs_bp.route('/download/pubkey/<int:user_id>')
@login_required
def download_pubkey(user_id):
    user = User.query.get_or_404(user_id)
    buf = io.BytesIO(user.public_key.encode())
    return send_file(buf, as_attachment=True,
                     download_name=f"pubkey_{user.username}.pem",
                     mimetype='text/plain')


# ── Export Laporan PDF ───────────────────────────────────────────────────────

@docs_bp.route('/export/pdf/<int:doc_id>')
@login_required
def export_pdf(doc_id):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors

    doc = Document.query.get_or_404(doc_id)
    signatures = Signature.query.filter_by(document_id=doc_id).all()

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    w, h = A4

    c.setFillColor(colors.HexColor('#0d9488'))
    c.rect(0, h - 80, w, 80, fill=True, stroke=False)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(40, h - 50, "SignDoc — Laporan Verifikasi")

    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, h - 110, f"Dokumen: {doc.original_filename}")
    c.setFont("Helvetica", 11)
    c.drawString(40, h - 130, f"Hash SHA-256: {doc.file_hash}")
    c.drawString(40, h - 148, f"Diupload oleh: {doc.uploader.username}")
    c.drawString(40, h - 166, f"Tanggal upload: {doc.uploaded_at.strftime('%d %B %Y %H:%M')}")

    y = h - 210
    c.setFont("Helvetica-Bold", 13)
    c.drawString(40, y, f"Tanda Tangan ({len(signatures)} penandatangan):")
    y -= 20

    for i, sig in enumerate(signatures, 1):
        valid = verify_signature(sig.signer.public_key, doc.file_hash, sig.signature_data)
        status = "VALID" if valid else "INVALID"
        color = colors.HexColor('#16a34a') if valid else colors.HexColor('#dc2626')
        c.setFont("Helvetica-Bold", 11)
        c.setFillColor(color)
        c.drawString(40, y, f"{i}. {sig.signer.username} — {status}")
        c.setFillColor(colors.black)
        c.setFont("Helvetica", 10)
        c.drawString(60, y - 14, f"Ditandatangani: {sig.signed_at.strftime('%d %B %Y %H:%M')}")
        c.drawString(60, y - 26, f"Hash saat tanda tangan: {sig.doc_hash_at_signing[:32]}...")
        y -= 50

        if y < 100:
            c.showPage()
            y = h - 60

    c.setFont("Helvetica", 9)
    c.setFillColor(colors.grey)
    c.drawString(40, 30, f"Digenerate oleh SignDoc pada {datetime.utcnow().strftime('%d %B %Y %H:%M')} UTC")
    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f"laporan_{doc.original_filename}.pdf",
                     mimetype='application/pdf')


# ── Download Signed PDF (dengan stamp QR) ────────────────────────────────────

def _build_stamp_overlay(signatures, doc, base_url, page_width, page_height):
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.lib import colors
    from reportlab.lib.utils import ImageReader

    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=(page_width, page_height))

    stamp_w = 160
    stamp_h = 80
    margin = 20
    gap = 10

    x_start = page_width - margin - stamp_w
    y_start = margin

    for idx, sig in enumerate(signatures):
        x = x_start - idx * (stamp_w + gap)
        y = y_start

        c.setStrokeColor(colors.black)
        c.setLineWidth(0.8)
        c.rect(x, y, stamp_w, stamp_h, fill=False, stroke=True)

        qr_size = 55
        qr_img = qrcode.make(f"{base_url}/verify/qr/{doc.id}")
        qr_buf = io.BytesIO()
        qr_img.save(qr_buf, format='PNG')
        qr_buf.seek(0)
        c.drawImage(ImageReader(qr_buf), x + 4, y + (stamp_h - qr_size) / 2,
                    width=qr_size, height=qr_size)

        text_x = x + qr_size + 8
        text_y = y + stamp_h - 14

        c.setFont("Helvetica", 6.5)
        c.setFillColor(colors.black)
        c.drawString(text_x, text_y, "Ditandatangani secara elektronik oleh:")

        c.setFont("Helvetica-Bold", 8)
        name = sig.signer.username.upper()
        if len(name) > 20:
            c.drawString(text_x, text_y - 11, name[:20])
            c.drawString(text_x, text_y - 21, name[20:])
        else:
            c.drawString(text_x, text_y - 11, name)

        c.setFont("Helvetica", 6)
        c.setFillColor(colors.grey)
        c.drawString(text_x, y + 5, sig.signed_at.strftime('%d %b %Y %H:%M'))

    c.save()
    buf.seek(0)
    return buf


@docs_bp.route('/download/signed/<int:doc_id>')
@login_required
def download_signed(doc_id):
    from reportlab.lib.pagesizes import A4
    from pypdf import PdfReader, PdfWriter
    import json

    doc = Document.query.get_or_404(doc_id)
    signatures = Signature.query.filter_by(document_id=doc_id).all()

    if not signatures:
        flash('Dokumen belum ditandatangani.', 'warning')
        return redirect(url_for('docs.document_detail', doc_id=doc_id))

    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], doc.filename)
    base_url = request.host_url.rstrip('/')
    ext = doc.original_filename.rsplit('.', 1)[-1].lower()

    signdoc_meta = {
        'signdoc': True,
        'document_id': doc.id,
        'original_filename': doc.original_filename,
        'file_hash': doc.file_hash,
        'signatures': [
            {
                'id': sig.id,
                'signer': sig.signer.username,
                'public_key': sig.signer.public_key,
                'signature_data': sig.signature_data,
                'doc_hash_at_signing': sig.doc_hash_at_signing,
                'signed_at': sig.signed_at.strftime('%d %B %Y %H:%M'),
            }
            for sig in signatures
        ]
    }

    if ext == 'pdf' and os.path.exists(filepath):
        reader = PdfReader(filepath)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        last_page = writer.pages[-1]
        pw = float(last_page.mediabox.width)
        ph = float(last_page.mediabox.height)

        stamp_buf = _build_stamp_overlay(signatures, doc, base_url, pw, ph)
        stamp_reader = PdfReader(stamp_buf)
        last_page.merge_page(stamp_reader.pages[0])

        writer.add_metadata({
            '/SignDocMeta': json.dumps(signdoc_meta),
            '/Producer': 'SignDoc — Digital Signature Platform',
            '/Creator': 'SignDoc'
        })

        output = io.BytesIO()
        writer.write(output)
        output.seek(0)
        return send_file(output, as_attachment=True,
                         download_name=f"signed_{doc.original_filename}",
                         mimetype='application/pdf')
    else:
        stamp_buf = _build_stamp_overlay(signatures, doc, base_url, A4[0], A4[1])
        return send_file(stamp_buf, as_attachment=True,
                         download_name=f"stamp_{doc.original_filename}.pdf",
                         mimetype='application/pdf')
