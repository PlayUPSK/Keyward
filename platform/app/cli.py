import click

from app import db


def register_cli(app):
    @app.cli.command("init-db")
    @click.option("--reset", is_flag=True, help="Drop all tables before creating them.")
    def init_db(reset):
        from app import models  # noqa: F401

        if reset:
            db.drop_all()
        db.create_all()
        click.echo("database tables created")

    @app.cli.command("create-admin")
    @click.option("--email", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    @click.option("--display-name", default=None)
    def create_admin(email, password, display_name):
        from app.services.auth import ADMIN_ROLE, create_local_user

        result, status_code = create_local_user(
            email=email,
            password=password,
            display_name=display_name,
            roles=["user", ADMIN_ROLE],
        )
        if status_code >= 400:
            raise click.ClickException(result["error"])
        click.echo(f"created admin {result['email']}")
