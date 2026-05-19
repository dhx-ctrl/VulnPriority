def test_admin_login_returns_token(client, test_env):
    response = client.post(
        "/api/login/",
        json={
            "username": test_env["admin_username"],
            "password": test_env["admin_password"],
        },
    )

    assert response.status_code == 200, response.text

    data = response.json()

    token = (
        data.get("access_token")
        or data.get("token")
        or data.get("api_key")
        or data.get("session_token")
    )

    assert token
    assert data.get("user") or data.get("username") or data.get("access_status") is not None


def test_wrong_admin_password_is_rejected(client, test_env):
    response = client.post(
        "/api/login/",
        json={
            "username": test_env["admin_username"],
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code in (400, 401, 403), response.text


def test_register_creates_pending_user(client, unique_username):
    response = client.post(
        "/api/register/",
        json={
            "username": unique_username,
            "password": "Test123!",
        },
    )

    assert response.status_code in (200, 201), response.text

    data = response.json()

    assert data.get("registered") is True or data.get("user") is not None

    user = data.get("user") or {}
    if user:
        assert user.get("username") == unique_username
        assert user.get("access_status") in ("pending", None)
