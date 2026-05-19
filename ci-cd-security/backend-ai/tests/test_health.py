def test_health_endpoint_returns_ok(client):
    response = client.get("/api/health/")

    assert response.status_code == 200, response.text

    data = response.json()

    assert data.get("status") == "ok"

    # The exact health payload can evolve, but it should expose backend/model state.
    assert "db" in data or "models" in data or "binary_model" in data

    if "models" in data:
        assert "clean" in data["models"]
        assert "operational_ranker" in data["models"]
