"""API integration tests."""

from fastapi.testclient import TestClient

from domasentrix.main import app

client = TestClient(app)


def test_root_endpoint() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["application"] == "DomaSentrix"


def test_health_endpoint() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_valid_target() -> None:
    response = client.post(
        "/v1/targets/validate",
        json={"domain": "EXAMPLE.COM"},
    )
    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()["normalized_domain"] == "example.com"
    assert response.json()["message"] == "Domain syntax is valid."


def test_invalid_target() -> None:
    response = client.post(
        "/v1/targets/validate",
        json={"domain": "127.0.0.1"},
    )
    assert response.status_code == 422
    assert "IP addresses are not accepted" in response.json()["detail"]
