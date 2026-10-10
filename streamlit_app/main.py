"""Streamlit entry point for the SecureSight public scanner."""
from __future__ import annotations

import io
import os
import time
from typing import Any

import streamlit as st


APP_URL = "https://secure-sight-cs.streamlit.app"
SECRET_KEYS = (
    "FLASK_SECRET_KEY",
    "RATELIMIT_STORAGE_URI",
    "SITE_URL",
    "DASHBOARD_ENCRYPTION_KEY",
    "DASHBOARD_DB_PATH",
)


def _load_streamlit_secrets() -> None:
    for key in SECRET_KEYS:
        if os.environ.get(key):
            continue
        try:
            value = st.secrets.get(key)
        except Exception:
            value = None
        if value:
            os.environ[key] = str(value)
    os.environ.setdefault("APP_ENV", "production")
    # The app's canonical origin follows its current Community Cloud subdomain;
    # an old value in Secrets can survive app renames and must not win here.
    os.environ["SITE_URL"] = APP_URL
    os.environ.setdefault("TRUSTED_HOSTS", "localhost,127.0.0.1")
    os.environ.setdefault("ALLOWED_ORIGINS", "")


@st.cache_resource(show_spinner=False)
def _backend_app():
    _load_streamlit_secrets()
    from app import create_app

    return create_app()


def _client(app):
    try:
        address = st.context.ip_address or "127.0.0.1"
    except Exception:
        address = "127.0.0.1"
    return app.test_client(), {"REMOTE_ADDR": address}


def _post(path: str, *, json_data=None, upload=None):
    app = _backend_app()
    client, environ = _client(app)
    if upload is not None:
        name, content, mime = upload
        response = client.post(
            path,
            data={"file": (io.BytesIO(content), name, mime)},
            environ_base=environ,
            base_url="http://localhost",
        )
    else:
        response = client.post(
            path,
            json=json_data,
            environ_base=environ,
            base_url="http://localhost",
        )
    return response


def _risk(result: dict[str, Any]) -> dict[str, Any]:
    value = result.get("assessment") or result.get("risk") or {}
    return value if isinstance(value, dict) else {}


def _verdict_title(verdict: str, risk_score: Any = None) -> str:
    return {
        "PHISHING": "Phishing indicators found",
        "MALICIOUS": "Threat indicators found",
        "LEGITIMATE": "No strong threat indicators found",
        "SUSPICIOUS": "Suspicious indicators found",
        "UNKNOWN": ("No strong threat indicators observed" if isinstance(risk_score, (int, float)) and risk_score < 40
                    else "Threat signals could not be scored" if risk_score is None
                    else "Threat indicators observed; some checks were incomplete"),
    }.get(str(verdict).upper(), "Analysis needs review")


def _observed_signals(risk: dict[str, Any], result: dict[str, Any]) -> list[Any]:
    candidates = (risk.get("top_signals") or result.get("top_signals") or
                 risk.get("reasons") or risk.get("signals") or [])
    if not isinstance(candidates, list):
        return []
    visible = []
    for item in candidates:
        if not isinstance(item, dict):
            visible.append(item)
            continue
        try:
            contribution = float(item.get("contribution") or 0)
        except (TypeError, ValueError):
            contribution = 0
        severity = str(item.get("severity", "")).upper()
        if contribution > 0 or severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            visible.append(item)
    return visible


def _render_result(result: dict[str, Any], mode: str) -> None:
    risk = _risk(result)
    verdict = str(risk.get("verdict") or result.get("verdict") or "UNKNOWN").upper()
    risk_score = risk.get("risk_score")
    media = result.get("synthetic_media") or {} if mode == "image" else {}
    image_label = None
    if mode == "image" and media.get("analysis_status") == "EXPERIMENTAL_ESTIMATE":
        image_label = ("AI-generation pattern likely" if media.get("classification") == "AI_GENERATED_PATTERN"
                       else "No strong AI-generation pattern flagged")
        st.subheader(image_label)
        st.caption("Image-origin screening is separate from whether the image is harmful, authentic, or safe to use.")
        st.write("**Threat screening:** " + _verdict_title(verdict, risk_score))
    elif mode == "image":
        st.subheader("AI-image model did not analyze this image")
        st.caption("No conclusion about AI origin or camera origin was produced.")
        st.write("**Threat screening:** " + _verdict_title(verdict, risk_score))
    else:
        st.subheader(_verdict_title(verdict, risk_score))
    score = risk_score
    model = media if mode == "image" else result.get("ml_result")
    if not isinstance(model, dict) and mode == "email":
        model = (result.get("email_analysis") or {}).get("experimental_model")
    model_score = model.get("model_score") if isinstance(model, dict) else None
    if model_score is None and isinstance(model, dict):
        model_score = model.get("probability")
    metrics = st.columns(3)
    metrics[0].metric("Observed risk score", f"{float(score):.1f} / 100" if isinstance(score, (float, int)) else "Not scored")
    metrics[1].metric("Model estimate", f"{float(model_score) * 100:.1f}%" if isinstance(model_score, (float, int)) else "Unavailable")
    metrics[2].metric("Checks", str(result.get("analysis_status") or result.get("status") or "Completed"))

    if mode == "image":
        classification = media.get("classification")
        if media.get("analysis_status") == "EXPERIMENTAL_ESTIMATE":
            st.info(f"Experimental model score: {float(media['model_score']) * 100:.1f}% · threshold {float(media['decision_threshold']) * 100:.1f}%. This score is not a probability that the image is AI-generated.")
        else:
            st.warning("The AI-image model did not produce an estimate for this file. Image origin is unconfirmed.")
        st.caption("This model was evaluated on one licensed AI-versus-human image dataset. It was not evaluated for deepfakes, face swaps, edited photographs, or all image generators. A low score does not prove an image is camera-made.")
        metadata = result.get("metadata") or {}
        st.write(f"**File:** {metadata.get('format', result.get('artifact', {}).get('format', 'Image'))} · {metadata.get('width', '?')} × {metadata.get('height', '?')} pixels")
        checks = (result.get("investigation") or {}).get("checks") or {}
        provenance = checks.get("c2pa") or {}
        st.write(f"**Trusted provenance:** {provenance.get('status', 'not checked')}. Missing metadata or provenance does not prove an image is fake.")
        forensics = result.get("forensics") or {}
        if forensics:
            st.caption("Image measurements are review clues, not validated manipulation scores.")
            st.json({key: forensics.get(key) for key in ("status", "recompression_mean_absolute_error", "median_residual_variance", "high_frequency_energy_fraction", "edge_gradient_mean") if key in forensics})
    elif mode == "email":
        email = result.get("email_analysis") or result
        auth = email.get("authentication") or {}
        st.write("**Sender authentication:** " + str(auth.get("status", "Could not be independently verified")))
        st.write("**Links checked:** " + str(len(email.get("urls") or [])))
        st.write("**Attachments inspected:** " + str(len(email.get("attachments") or [])))
        st.caption("A clean content scan does not prove that the sender is genuine. Verify payment, password, and account requests through a known contact method.")
    else:
        domain = result.get("domain_intelligence") or {}
        registration = domain.get("registration") or {}
        age = registration.get("domain_age_days")
        st.write(f"**Domain age:** {f'{age} days' if isinstance(age, (int, float)) else 'Unavailable'}")
        st.write("**Website checks:** " + str((result.get("web_intelligence") or {}).get("status", "See scan details")))
        st.caption("A low score or established domain does not guarantee safety. Check the full destination before opening it.")

    reasons = _observed_signals(risk, result)
    signal_titles = {
        "ml.phishing": "URL model detected a small phishing-pattern signal",
        "url.ip_host": "URL uses an IP address instead of a domain name",
        "url.at_authority": "URL contains an @ sign in its authority section",
        "url.idn": "URL uses an internationalized hostname",
        "url.typosquatting": "Hostname resembles a known brand domain",
        "url.lure_keywords": "URL contains a suspicious lure phrase",
        "url.length": "URL is unusually long",
        "domain.young": "Domain registration is recent",
        "tls.invalid": "TLS certificate could not be verified",
    }
    if reasons:
        st.markdown("**Observed indicators**")
        for item in reasons[:6]:
            if isinstance(item, dict):
                signal_id = item.get("signal_id")
                st.write("• " + str(item.get("label") or item.get("message") or signal_titles.get(signal_id, "Observed signal")))
            else:
                st.write("• " + str(item))
    details = result.get("investigation") or result.get("email_analysis") or result
    with st.expander("Technical details and evidence"):
        if isinstance(details, dict):
            safe_keys = ("coverage", "checks", "warnings", "errors", "domain_intelligence", "website_intelligence", "explanation", "risk", "synthetic_media", "metadata", "provenance", "forensics", "ocr", "qr", "authentication", "attachments", "urls")
            safe_details = {key: details[key] for key in safe_keys if key in details}
            st.json(safe_details or details)
        else:
            st.write(details)
    st.caption("For decision support only. No automated scan can guarantee a file, email, or website is safe.")


def _show_error(response) -> None:
    try:
        body = response.get_json() or {}
    except Exception:
        body = {}
    code = ((body.get("error") or {}).get("code") or body.get("error_code") or "ANALYSIS_FAILED")
    st.error(f"The scan could not be completed ({code}). Try again with a supported file or URL.")


def main() -> None:
    st.set_page_config(page_title="SecureSight", page_icon="🛡️", layout="centered")
    st.title("SecureSight")
    st.write("Check a link, email file, or image for observable security signals.")
    st.caption("Results are decision support. A clean result is not proof that content is safe.")

    url_tab, email_tab, image_tab = st.tabs(["Website link", "Email file", "Image"])
    with url_tab:
        with st.form("url_scan"):
            url = st.text_input("Website address", placeholder="https://example.com")
            scan_url = st.form_submit_button("Check link", type="primary")
        if scan_url:
            try:
                with st.spinner("Checking the website and domain signals…"):
                    response = _post("/api/v1/scan", json_data={"url": url})
                if response.status_code == 200:
                    _render_result(response.get_json(), "url")
                else:
                    _show_error(response)
            except Exception as exc:
                st.error("SecureSight could not start the scan. Check deployment secrets and try again.")
                st.caption(type(exc).__name__)

    with email_tab:
        with st.form("email_scan"):
            email_file = st.file_uploader("Choose an email file", type=["eml", "pdf", "docx", "xml"], key="email_file")
            scan_email = st.form_submit_button("Check email", type="primary")
        if scan_email:
            if not email_file:
                st.warning("Choose an email file first.")
            elif email_file.size > 2 * 1024 * 1024:
                st.error("Email files must be 2 MB or smaller.")
            else:
                try:
                    with st.spinner("Inspecting the message, attachments, and links…"):
                        response = _post("/api/v1/email/analyze", upload=(email_file.name, email_file.getvalue(), email_file.type or "application/octet-stream"))
                        if response.status_code != 202:
                            _show_error(response)
                        else:
                            ticket = response.get_json()
                            client, environ = _client(_backend_app())
                            result = None
                            for _ in range(120):
                                time.sleep(0.25)
                                poll = client.get(ticket["poll_url"], headers={"Authorization": "Bearer " + ticket["token"]}, environ_base=environ, base_url="http://localhost")
                                job = poll.get_json() or {}
                                if job.get("state") in {"PARTIAL", "COMPLETE", "FAILED"}:
                                    result = job.get("result")
                                    break
                            if not isinstance(result, dict):
                                st.warning("The email scan is still running or could not return a result. Please retry shortly.")
                            elif result.get("analysis_status") == "FAILED":
                                st.error("Email analysis could not be completed. Try a supported EML, PDF, DOCX, or XML file.")
                            else:
                                _render_result(result, "email")
                except Exception as exc:
                    st.error("SecureSight could not start the email scan. Check deployment secrets and try again.")
                    st.caption(type(exc).__name__)

    with image_tab:
        with st.form("image_scan"):
            image_file = st.file_uploader("Choose an image", type=["png", "jpg", "jpeg", "webp"], key="image_file")
            scan_image = st.form_submit_button("Check image", type="primary")
        st.caption("PNG, JPEG, or WebP · up to 5 MB. Uploads are processed for this scan and are not saved by the scanner.")
        if scan_image:
            if not image_file:
                st.warning("Choose an image first.")
            elif image_file.size > 5 * 1024 * 1024:
                st.error("Images must be 5 MB or smaller.")
            else:
                try:
                    with st.spinner("Inspecting image metadata, provenance, text, and AI-generation patterns…"):
                        response = _post("/api/v1/media/analyze", upload=(image_file.name, image_file.getvalue(), image_file.type or "application/octet-stream"))
                    if response.status_code == 200:
                        _render_result(response.get_json(), "image")
                    else:
                        _show_error(response)
                except Exception as exc:
                    st.error("SecureSight could not start the image scan. Check deployment secrets and try again.")
                    st.caption(type(exc).__name__)

    st.divider()
    st.caption("Uploads are handled in memory and temporary worker storage. Do not submit confidential files to a public demo.")


if __name__ == "__main__":
    main()
