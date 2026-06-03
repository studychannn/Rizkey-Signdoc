from flask import Blueprint, render_template, request
from models import Document, Signature
from crypto_utils import hash_file, verify_signature

verify_bp = Blueprint('verify', __name__)

@verify_bp.route('/verify', methods=['GET', 'POST'])
def verify():
    result = None
    if request.method == 'POST':
        verify_mode = request.form.get('verify_mode', 'id')

        # ── Mode 1: Verifikasi via Signature ID ──────────────────────────────
        if verify_mode == 'id':
            sig_id = request.form.get('signature_id', '').strip()
            if not sig_id:
                result = {'error': 'Signature ID wajib diisi.'}
            else:
                sig = Signature.query.get(sig_id)
                if not sig:
                    result = {'error': f'Signature ID "{sig_id}" tidak ditemukan.'}
                else:
                    doc = sig.document
                    is_valid = verify_signature(sig.signer.public_key, sig.doc_hash_at_signing, sig.signature_data)

                    # Ambil semua signature dari dokumen yang sama
                    all_signatures = Signature.query.filter_by(document_id=doc.id).order_by(Signature.signed_at).all()
                    all_sigs_detail = []
                    for s in all_signatures:
                        all_sigs_detail.append({
                            'id': s.id,
                            'signer': s.signer.username,
                            'signed_at': s.signed_at.strftime('%d %B %Y %H:%M'),
                            'valid': verify_signature(s.signer.public_key, s.doc_hash_at_signing, s.signature_data),
                            'doc_hash': s.doc_hash_at_signing,
                            'is_queried': s.id == sig.id,
                        })

                    result = {
                        'valid': is_valid,
                        'signer': sig.signer.username,
                        'signed_at': sig.signed_at.strftime('%d %B %Y %H:%M'),
                        'doc_hash': sig.doc_hash_at_signing,
                        'document_name': doc.original_filename,
                        'signature_id': sig.id,
                        'all_signatures': all_sigs_detail,
                        'total_signers': len(all_sigs_detail),
                        'mode': 'id',
                    }

        # ── Mode 2: Verifikasi via Upload File Dokumen + File .sig ───────────
        elif verify_mode == 'file':
            doc_file = request.files.get('doc_file')
            sig_file = request.files.get('sig_file')
            pubkey_file = request.files.get('pubkey_file')

            if not doc_file or doc_file.filename == '':
                result = {'error': 'File dokumen wajib diunggah.'}
            elif not sig_file or sig_file.filename == '':
                result = {'error': 'File signature (.sig) wajib diunggah.'}
            elif not pubkey_file or pubkey_file.filename == '':
                result = {'error': 'File public key (.pem) wajib diunggah.'}
            else:
                try:
                    doc_bytes = doc_file.read()
                    doc_hash = hash_file(doc_bytes)

                    sig_data = sig_file.read().decode('utf-8').strip()
                    public_key_pem = pubkey_file.read().decode('utf-8').strip()

                    is_valid = verify_signature(public_key_pem, doc_hash, sig_data)

                    # Deteksi penyebab INVALID
                    invalid_reason = None
                    if not is_valid:
                        # Cek apakah pubkey valid formatnya
                        try:
                            from cryptography.hazmat.primitives.serialization import load_pem_public_key
                            from cryptography.hazmat.backends import default_backend
                            load_pem_public_key(public_key_pem.encode(), backend=default_backend())
                            pubkey_ok = True
                        except Exception:
                            pubkey_ok = False
                            invalid_reason = 'pubkey'

                        # Cek apakah sig valid formatnya (base64)
                        if pubkey_ok:
                            import base64
                            try:
                                base64.b64decode(sig_data)
                                sig_ok = True
                            except Exception:
                                sig_ok = False
                                invalid_reason = 'sig'

                            # Kalau keduanya valid format tapi verifikasi tetap gagal
                            # → kemungkinan dokumen dimodifikasi atau pubkey tidak cocok
                            if sig_ok:
                                invalid_reason = 'mismatch'

                    result = {
                        'valid': is_valid,
                        'doc_hash': doc_hash,
                        'document_name': doc_file.filename,
                        'mode': 'file',
                        'invalid_reason': invalid_reason,
                    }
                except Exception as e:
                    result = {'error': f'Gagal memproses file: {str(e)}'}

    return render_template('verify.html', result=result)


@verify_bp.route('/verify/qr/<int:doc_id>')
def verify_qr(doc_id):
    """Public QR verification — no login required."""
    doc = Document.query.get_or_404(doc_id)
    signatures = Signature.query.filter_by(document_id=doc_id).all()
    sig_results = []
    for sig in signatures:
        valid = verify_signature(sig.signer.public_key, sig.doc_hash_at_signing, sig.signature_data)
        sig_results.append({
            'signer': sig.signer.username,
            'signed_at': sig.signed_at.strftime('%d %B %Y %H:%M'),
            'valid': valid,
        })
    return render_template('verify_qr.html', doc=doc, sig_results=sig_results)
