from datetime import timedelta, timezone

from flask import current_app, jsonify, request

from app import db
from app.models.rate_limit import RateLimitBucket
from app.models.base import utcnow


def register_security(app):
    @app.before_request
    def enforce_rate_limit():
        if request.endpoint == "static":
            return None
        limited, retry_after = check_rate_limit(
            key=f"{request.remote_addr or 'unknown'}:{request.endpoint or request.path}",
            limit=current_app.config["RATE_LIMIT_MAX_REQUESTS"],
            window_seconds=current_app.config["RATE_LIMIT_WINDOW_SECONDS"],
        )
        if limited:
            response = jsonify({"error": "rate_limited", "retry_after_seconds": retry_after})
            response.status_code = 429
            response.headers["Retry-After"] = str(retry_after)
            return response
        return None

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response


def check_rate_limit(*, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
    now = utcnow()
    bucket = db.session.get(RateLimitBucket, key)
    reset_at = _aware(bucket.window_reset_at) if bucket else None
    if bucket is None or reset_at <= now:
        bucket = RateLimitBucket(
            key=key,
            count=1,
            window_reset_at=now + timedelta(seconds=window_seconds),
        )
        db.session.merge(bucket)
        db.session.commit()
        return False, window_seconds

    bucket.count += 1
    db.session.commit()
    retry_after = max(1, int((_aware(bucket.window_reset_at) - now).total_seconds()))
    return bucket.count > limit, retry_after


def _aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
