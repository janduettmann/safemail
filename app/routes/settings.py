from flask import Blueprint, redirect, render_template, url_for
from flask_login import login_required

settings_bp: Blueprint = Blueprint(name="settings", import_name=__name__)

# Whitelist of valid settings page keys.
# Validated against the URL parameter to prevent path traversal in the
# dynamic ``{% include %}`` resolved inside settings.html.
SETTINGS_PAGES: set[str] = {"account", "mail_accounts", "scan_behavior", "other"}


@settings_bp.route(rule="/settings", methods=["GET"])
@login_required
def settings():
    """Redirects bare ``/settings`` to the default sub-page."""
    return redirect(url_for("settings.settings_page", page="account"))


@settings_bp.route(rule="/settings/<page>", methods=["GET"])
@login_required
def settings_page(page: str):
    """Renders ``/settings/<page>`` for one of the whitelisted sub-pages.

    Args:
        page: Sub-page key; must be one of ``SETTINGS_PAGES``. Unknown
            keys are redirected to the account page.

    Returns:
        Rendered ``settings.html`` with the requested partial included,
        or a redirect to the account page on an unknown key.
    """
    if page not in SETTINGS_PAGES:
        return redirect(url_for("settings.settings_page", page="account"))
    return render_template("settings.html", active_page=page)
