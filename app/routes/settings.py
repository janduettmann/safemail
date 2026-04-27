from flask import Blueprint, redirect, render_template, request, flash, url_for

settings_bp: Blueprint = Blueprint(name="settings", import_name=__name__)

@settings_bp.route(rule="/settings", methods=["POST", "GET"])
def settings():
    return render_template('settings.html')
