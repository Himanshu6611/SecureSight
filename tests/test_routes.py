def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"SecureSight" in response.data or b"Secure Sight" in response.data

def test_url_analysis_post(client):
    response = client.post("/", data={
        "check_type": "url",
        "url": "http://malicious-site.com"
    })
    assert response.status_code == 200
    assert b"Threat Verdict" in response.data or b"Detection Result" in response.data

def test_email_analysis_post(client):
    response = client.post("/", data={
        "check_type": "email",
        "email_text": "Hey, this is a normal email."
    })
    assert response.status_code == 200
    assert b"Threat Verdict" in response.data or b"Detection Result" in response.data

def test_robots_txt(client):
    response = client.get("/robots.txt")
    assert response.status_code == 200
    assert b"User-agent: *" in response.data
    assert b"Sitemap:" in response.data
    assert b"Disallow: /api/" in response.data

def test_sitemap_xml(client):
    response = client.get("/sitemap.xml")
    assert response.status_code == 200
    assert response.mimetype == "application/xml"
    assert b"<loc>" in response.data

def test_favicon(client):
    response = client.get("/favicon.ico")
    assert response.status_code == 200

def test_api_analyze_noindex(client):
    response = client.post("/api/analyze", json={"url": "http://example.com"})
    assert response.status_code == 200
    assert response.headers.get("X-Robots-Tag") == "noindex, nofollow"

def test_api_analyze_missing_url(client):
    response = client.post("/api/analyze", json={})
    assert response.status_code == 400
    assert b"No URL provided" in response.data

def test_image_analysis_post_no_file(client):
    response = client.post("/", data={"check_type": "image"})
    assert response.status_code == 200
    assert b"Please upload an image" in response.data

