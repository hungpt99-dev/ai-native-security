"""Asset inventory API behaviour."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_asset_crud(client: TestClient) -> None:
    payload = {
        "name": "payments",
        "repo_url": "https://github.com/example/payments",
        "default_branch": "main",
        "description": "Payments service",
        "monitoring_enabled": True,
        "scan_interval_minutes": 120,
    }
    created = client.post("/api/v1/assets", json=payload)
    assert created.status_code == 201, created.text
    asset = created.json()
    assert asset["provider"] == "GITHUB"
    assert asset["has_credential"] is False

    fetched = client.get(f"/api/v1/assets/{asset['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "payments"

    updated = client.put(
        f"/api/v1/assets/{asset['id']}",
        json={"name": "payments-api", "monitoring_enabled": False},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "payments-api"
    assert updated.json()["monitoring_enabled"] is False

    listing = client.get("/api/v1/assets", params={"page": 1, "page_size": 10})
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == asset["id"]

    deleted = client.delete(f"/api/v1/assets/{asset['id']}")
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/assets/{asset['id']}").status_code == 404


def test_duplicate_repository_conflicts(client: TestClient) -> None:
    payload = {"name": "a", "repo_url": "https://github.com/example/dup"}
    assert client.post("/api/v1/assets", json=payload).status_code == 201
    duplicate = client.post("/api/v1/assets", json={**payload, "name": "b"})
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "conflict"


def test_invalid_url_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/assets", json={"name": "bad", "repo_url": "file:///etc/passwd"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_update_credential_rotation_and_clear(client: TestClient) -> None:
    created = client.post(
        "/api/v1/assets",
        json={
            "name": "private",
            "repo_url": "https://github.com/example/private",
            "access_token": "ghp_firsttoken1234567890",
        },
    ).json()
    assert created["has_credential"] is True

    rotated = client.put(
        f"/api/v1/assets/{created['id']}",
        json={"access_token": "ghp_secondtoken0987654321"},
    )
    assert rotated.status_code == 200
    assert "ghp_secondtoken0987654321" not in rotated.text

    cleared = client.put(f"/api/v1/assets/{created['id']}", json={"clear_credential": True})
    assert cleared.json()["has_credential"] is False


def test_filtering_and_pagination(client: TestClient) -> None:
    for index in range(3):
        client.post(
            "/api/v1/assets",
            json={
                "name": f"github-{index}",
                "repo_url": f"https://github.com/example/github-{index}",
            },
        )
    client.post(
        "/api/v1/assets",
        json={"name": "gitlab-one", "repo_url": "https://gitlab.com/example/gitlab-one"},
    )

    page = client.get("/api/v1/assets", params={"page": 1, "page_size": 2}).json()
    assert page["total"] == 4
    assert len(page["items"]) == 2
    assert page["pages"] == 2

    gitlab = client.get("/api/v1/assets", params={"provider": "gitlab"}).json()
    assert gitlab["total"] == 1
    assert gitlab["items"][0]["name"] == "gitlab-one"

    search = client.get("/api/v1/assets", params={"search": "github-1"}).json()
    assert search["total"] == 1


def test_unknown_asset_returns_envelope(client: TestClient) -> None:
    response = client.get("/api/v1/assets/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
    assert "traceback" not in response.text.lower()
