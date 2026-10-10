from streamlit_app.main import _observed_signals, _verdict_title


def test_result_panel_hides_zero_contribution_features():
    result = {"top_signals": [
        {"signal_id": "url.ip_host", "contribution": 0.0, "severity": "INFO"},
        {"signal_id": "ml.phishing", "contribution": 0.26, "severity": "INFO"},
        {"signal_id": "url.typosquatting", "contribution": 0.0, "severity": "HIGH"},
    ]}
    assert [item["signal_id"] for item in _observed_signals({}, result)] == [
        "ml.phishing", "url.typosquatting"
    ]


def test_result_panel_summarizes_low_risk_without_claiming_legitimacy():
    assert _verdict_title("UNKNOWN", 0.3) == "No strong threat indicators observed"
    assert _verdict_title("UNKNOWN", None) == "Threat signals could not be scored"
