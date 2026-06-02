def test_health_endpoint_returns_ok(client):
    response = client.get("/api/health")
    assert response.status_code == 200

    data = response.json()

    assert "auth" in data
    assert "db" in data

    assert data["auth"]["configured"] is True
    assert data["auth"]["dashboard_login"] is True
    assert data["auth"]["header"] == "X-API-Key"
