# routes
# app/routes.py
import pandas as pd
from flask import Blueprint, request, render_template, jsonify, current_app
from utils.feature_extraction import extract_features
from utils.email_extraction import extract_email_features
from utils.reputation import compute_risk_score, explain_risk
from utils.model import load_ensemble, load_email_model, predict_proba, explain_prediction
import werkzeug
from utils.image_analysis import analyze_image

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

bp = Blueprint("main", __name__)

# Load models once on first import
MODEL = load_ensemble()
EMAIL_MODEL = load_email_model()

@bp.route("/", methods=["GET", "POST"])
def index():
    result = None
    explanation = None
    error_msg = None
    check_type = request.form.get("check_type", "url") # Default to url

    if request.method == "POST":
        if check_type == "url":
            url = request.form.get("url", "").strip()
            if not url:
                error_msg = "Please enter a URL."
            else:
                try:
                    # ---------- Feature extraction ----------
                    feats = extract_features(url)
                    feat_df = pd.DataFrame([feats])

                    # ---------- ML probability ----------
                    ml_prob = predict_proba(MODEL, feat_df) if MODEL else 0.5

                    # ---------- Reputation / risk ----------
                    risk = compute_risk_score(url, feats)

                    # ---------- Combine ----------
                    decision = "Phishing" if (risk >= 70 or ml_prob >= 0.85) else "Legitimate"

                    result = {
                        "type": "url",
                        "url": url,
                        "decision": decision,
                        "ml_probability": round(ml_prob, 3),
                        "risk_score": risk
                    }
                    explanation = {
                        "ml_detail": explain_prediction(url, ml_prob, risk),
                        "risk_breakdown": explain_risk(url, feats)
                    }
                except Exception as exc:
                    current_app.logger.exception("Error processing URL")
                    error_msg = f"Unable to analyse the URL: {str(exc)}"
        
        elif check_type == "email":
            email_text = request.form.get("email_text", "").strip()
            if not email_text:
                error_msg = "Please enter email content."
            else:
                try:
                    feats = extract_email_features(email_text)
                    feat_df = pd.DataFrame([feats])
                    
                    if EMAIL_MODEL:
                        ml_prob = float(EMAIL_MODEL.predict_proba(feat_df)[:, 1][0])
                    else:
                        ml_prob = 0.5
                    
                    decision = "Phishing" if ml_prob >= 0.7 else "Legitimate"
                    
                    result = {
                        "type": "email",
                        "content_snippet": email_text[:100] + "...",
                        "decision": decision,
                        "ml_probability": round(ml_prob, 3)
                    }
                    explanation = {
                        "features": feats
                    }
                except Exception as exc:
                    current_app.logger.exception("Error processing Email")
                    error_msg = f"Unable to analyse the email: {str(exc)}"

        elif check_type == "image":
            if "image_file" not in request.files:
                error_msg = "Please upload an image."
            else:
                file = request.files["image_file"]
                if file.filename == '':
                    error_msg = "No selected file."
                elif file:
                    # Check file size by seeking
                    file.seek(0, 2)
                    file_size = file.tell()
                    file.seek(0)
                    if file_size > MAX_FILE_SIZE:
                        error_msg = "File size exceeds 5MB limit."
                    elif not allowed_file(file.filename):
                        error_msg = "Invalid file type. Only PNG, JPG, JPEG, WEBP allowed."
                    else:
                        try:
                            filename = werkzeug.utils.secure_filename(file.filename)
                            analysis_results = analyze_image(file)
                            
                            decision = "AI Generated" if analysis_results["is_ai_generated"] else "Real Image"
                            
                            result = {
                                "type": "image",
                                "filename": filename,
                                "decision": decision,
                                "risk_score": analysis_results["risk_score"],
                                "confidence": analysis_results["confidence"],
                                "signals": analysis_results["signals"],
                                "ela_score": analysis_results["ela_score"],
                                "ml_risk": analysis_results["ml_risk"],
                                "fft_score": analysis_results["fft_score"],
                                "noise_score": analysis_results["noise_score"]
                            }
                        except Exception as exc:
                            current_app.logger.exception("Error processing Image")
                            error_msg = f"Unable to analyse the image: {str(exc)}"

    return render_template(
        "index.html",
        result=result,
        explanation=explanation,
        error_msg=error_msg,
        check_type=check_type
    )
@bp.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided."}), 400

    try:
        # ---------- Feature extraction ----------
        feats = extract_features(url)
        feat_df = pd.DataFrame([feats])

        # ---------- ML probability ----------
        ml_prob = predict_proba(MODEL, feat_df)

        # ---------- Reputation / risk ----------
        risk = compute_risk_score(url, feats)

        # ---------- Combine ----------
        decision = "Phishing" if (risk >= 70 or ml_prob >= 0.85) else "Legitimate"

        result = {
            "url": url,
            "decision": decision,
            "ml_probability": round(ml_prob, 3),
            "risk_score": risk,
            "explanation": {
                "ml_detail": explain_prediction(url, ml_prob, risk),
                "risk_breakdown": explain_risk(url, feats)
            }
        }

        return jsonify(result)

    except Exception as exc:
        current_app.logger.exception("Error processing URL")
        return jsonify({"error": f"Unable to analyse the URL: {str(exc)}"}), 500