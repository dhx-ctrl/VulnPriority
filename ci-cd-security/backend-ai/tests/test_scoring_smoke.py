def test_risk_score_endpoint_returns_dual_model_scores(client, auth_headers):
    payload = {
        "cve_id": "CVE-2021-23337",
        "year": 2021,
        "cwe": "CWE-94",
        "title": "Command injection vulnerability in lodash",
        "description": "Example vulnerable package finding used for smoke testing.",
        "component_name": "lodash",
        "component_version": "4.17.20",
        "package_name": "lodash",
        "scanner_type": "SCA",
        "scanner_severity": "High",
        "cvss_score": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "has_cve": True,
        "is_static": False,
        "is_dynamic": False,
        "references_count": 2,
        "github_reviewed": False,
        "has_patch_ref": True,
        "has_advisory_ref": True,
    }

    response = client.post(
        "/api/risk-score/",
        headers=auth_headers,
        json=payload,
    )

    # Some backend versions expose the same logic through /api/score-finding/.
    if response.status_code == 404:
        response = client.post(
            "/api/score-finding/",
            headers=auth_headers,
            json=payload,
        )

    assert response.status_code == 200, response.text

    data = response.json()

    assert "risk_score" in data
    assert "operational_rank_score" in data
    assert "clean_ai_score" in data

    assert isinstance(data["risk_score"], (int, float))
    assert isinstance(data["operational_rank_score"], (int, float))
    assert isinstance(data["clean_ai_score"], (int, float))

    assert 0 <= data["risk_score"] <= 100
    assert 0 <= data["operational_rank_score"] <= 100
    assert 0 <= data["clean_ai_score"] <= 100

    assert data.get("operational_model_version")
    assert data.get("clean_model_version")
