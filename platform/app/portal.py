from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app.services.auth import current_user, require_login
from app.services.devices import approve_device_enrollment, enrollment_callback_url, pending_enrollment_for_code
from app.services.portal import accessible_servers_for_user, user_devices

bp = Blueprint("portal", __name__)


@bp.get("/")
@require_login
def index():
    user = current_user()
    return render_template(
        "portal/index.html",
        servers=accessible_servers_for_user(user.id),
        devices=user_devices(user.id),
    )


@bp.get("/devices/enroll")
@require_login
def enroll_device():
    user = current_user()
    return render_template("portal/enroll_device.html", user=user)


@bp.get("/devices/approve")
@require_login
def approve_device():
    code = request.args.get("code", "")
    enrollment = pending_enrollment_for_code(code)
    return render_template("portal/approve_device.html", code=code, enrollment=enrollment)


@bp.post("/devices/approve")
@require_login
def approve_device_post():
    code = request.form.get("code", "")
    enrollment = pending_enrollment_for_code(code)
    result, status_code = approve_device_enrollment(
        current_user(),
        code,
        password=request.form.get("password"),
        authenticated_at=session.get("authenticated_at"),
    )
    if status_code >= 400:
        flash(result.get("error", "device_approval_failed"), "danger")
        return redirect(url_for("portal.approve_device", code=code))
    return render_template(
        "portal/device_approved.html",
        enrollment=enrollment,
        callback_url=enrollment_callback_url(enrollment) if enrollment else None,
    )
