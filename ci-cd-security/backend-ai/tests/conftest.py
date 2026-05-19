import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def backend_dir() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def test_env(tmp_path_factory, backend_dir):
    """
    Prepare a safe local test environment before importing main.py.

    The backend loads models and initializes SQLite during import/startup,
    so these env vars must be set before importing the FastAPI app.
    """
    db_dir = tmp_path_factory.mktemp("vulnpriority_test_db")
    db_path = db_dir / "ai_scores_test.db"

    os.environ["DB_PATH"] = str(db_path)

    os.environ["DASHBOARD_USERNAME"] = "admin"
    os.environ["DASHBOARD_PASSWORD"] = "Admin123!"

    os.environ["API_AUTH_TOKEN"] = "test-api-token"
    os.environ["AI_API_KEY"] = "test-api-token"

    os.environ["DASHBOARD_ORIGINS"] = (
        "http://127.0.0.1:5173,"
        "http://localhost:5173,"
        "http://127.0.0.1:5500,"
        "http://localhost:5500"
    )

    os.environ["DEFECTDOJO_URL"] = "http://127.0.0.1:8080"
    os.environ["DEFECTDOJO_API_KEY"] = "dummy-test-key"
    os.environ["DEFECTDOJO_PRODUCT_ID"] = ""

    os.environ["AI_CLEAN_MODEL_DIR"] = str(
        backend_dir / "model_output_FINAL_clean_minimal_features"
    )
    os.environ["AI_RANKER_MODEL_DIR"] = str(
        backend_dir / "model_output_EPSS_operational_ranker"
    )

    # Make sure tests can import backend-ai/main.py even when pytest is run
    # from the repository root.
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    return {
        "db_path": db_path,
        "admin_username": "admin",
        "admin_password": "Admin123!",
    }


@pytest.fixture(scope="session")
def app_module(test_env):
    """
    Import main.py only after test env is configured.
    """
    import main

    return main


@pytest.fixture(scope="session")
def client(app_module):
    with TestClient(app_module.app) as test_client:
        yield test_client


@pytest.fixture()
def unique_username():
    return f"test_user_{uuid.uuid4().hex[:10]}"


@pytest.fixture()
def admin_token(client, test_env):
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

    assert token, f"No token returned by login endpoint: {data}"
    return token


@pytest.fixture()
def auth_headers(admin_token):
    return {"X-API-Key": admin_token}
