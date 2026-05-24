from flask import Blueprint, Response, flash, redirect, render_template, request, session, url_for

from app.models.base import utcnow

from app.services.auth import login_federated_user, login_local_user, login_or_create_user, logout_user, register_local_user
from app.services.sso import enabled_sso_providers, oidc_authorization_url, oidc_callback_payload, saml_acs_payload, saml_login_url, saml_metadata_xml

bp = Blueprint("auth", __name__)


@bp.get("/login")
def login():
    return render_template("auth/login.html", sso=enabled_sso_providers())


@bp.post("/login")
def login_post():
    user, error = login_local_user(
        email=request.form.get("email", ""),
        password=request.form.get("password", ""),
    )
    if error:
        flash(error, "danger")
        return redirect(url_for("auth.login"))

    session["user_id"] = str(user.id)
    session["authenticated_at"] = utcnow().isoformat()
    session.permanent = True
    return redirect(url_for("portal.index"))


@bp.get("/register")
def register():
    return render_template("auth/register.html")


@bp.post("/register")
def register_post():
    user, error = register_local_user(
        email=request.form.get("email", ""),
        password=request.form.get("password", ""),
        display_name=request.form.get("display_name"),
    )
    if error:
        flash(error, "danger")
        return redirect(url_for("auth.register"))

    session["user_id"] = str(user.id)
    session["authenticated_at"] = utcnow().isoformat()
    session.permanent = True
    return redirect(url_for("portal.index"))


@bp.post("/dev-login")
def dev_login_post():
    user, error = login_or_create_user(
        email=request.form.get("email", ""),
        display_name=request.form.get("display_name"),
    )
    if error:
        flash(error, "danger")
        return redirect(url_for("auth.login"))

    session["user_id"] = str(user.id)
    session["authenticated_at"] = utcnow().isoformat()
    session.permanent = True
    return redirect(url_for("portal.index"))


@bp.get("/oidc/login")
def oidc_login():
    redirect_url, error = oidc_authorization_url()
    if error:
        flash(error, "danger")
        return redirect(url_for("auth.login"))
    return redirect(redirect_url)


@bp.get("/oidc/callback")
def oidc_callback():
    payload, error = oidc_callback_payload(request.args)
    if error:
        flash(error, "danger")
        return redirect(url_for("auth.login"))
    return _finish_sso_login(payload)


@bp.get("/saml/login")
def saml_login():
    redirect_url, error = saml_login_url()
    if error:
        flash(error, "danger")
        return redirect(url_for("auth.login"))
    return redirect(redirect_url)


@bp.post("/saml/acs")
def saml_acs():
    payload, error = saml_acs_payload()
    if error:
        flash(error, "danger")
        return redirect(url_for("auth.login"))
    return _finish_sso_login(payload)


@bp.get("/saml/metadata")
def saml_metadata():
    metadata, error = saml_metadata_xml()
    if error:
        return Response(error, status=400, mimetype="text/plain")
    return Response(metadata, mimetype="application/samlmetadata+xml")


@bp.post("/logout")
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


def _finish_sso_login(payload: dict):
    user, error = login_federated_user(
        email=payload.get("email", ""),
        display_name=payload.get("display_name"),
        provider=payload.get("provider", "sso"),
        external_id=payload.get("external_id"),
        groups=payload.get("groups") or [],
        group_source=payload.get("group_source"),
        attribute_keys=payload.get("attribute_keys") or [],
    )
    if error:
        flash(error, "danger")
        return redirect(url_for("auth.login"))

    session["user_id"] = str(user.id)
    session["authenticated_at"] = utcnow().isoformat()
    session.permanent = True
    return redirect(url_for("portal.index"))
