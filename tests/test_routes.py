def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Secure Sight" in response.data

def test_url_analysis_post(client):
    response = client.post("/", data={
        "check_type": "url",
        "url": "http://malicious-site.com"
    })
    assert response.status_code == 200
    assert b"Detection Result" in response.data

def test_email_analysis_post(client):
    response = client.post("/", data={
        "check_type": "email",
        "email_text": "Hey, this is a normal email."
    })
    assert response.status_code == 200
    assert b"Detection Result" in response.data

