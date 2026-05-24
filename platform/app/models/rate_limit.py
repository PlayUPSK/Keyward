from app import db


class RateLimitBucket(db.Model):
    __tablename__ = "rate_limit_buckets"

    key = db.Column(db.Text, primary_key=True)
    count = db.Column(db.Integer, nullable=False, default=0)
    window_reset_at = db.Column(db.DateTime(timezone=True), nullable=False)
