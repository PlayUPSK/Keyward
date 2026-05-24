from app import create_app


def test_healthz():
    app = create_app("app.config.TestConfig")
    client = app.test_client()

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
