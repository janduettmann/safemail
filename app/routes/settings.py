from flask import Blueprint, render_template
from flask_login import login_required

settings_bp: Blueprint = Blueprint(name="settings", import_name=__name__)

@settings_bp.route(rule="/settings", methods=["POST", "GET"])
@login_required
def settings():
    return render_template('settings.html')
