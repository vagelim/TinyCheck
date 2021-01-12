#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, send_from_directory, jsonify, redirect
from app.blueprints.network import network_bp
from app.blueprints.capture import capture_bp
from app.blueprints.device import device_bp
from app.blueprints.analysis import analysis_bp
from app.blueprints.save import save_bp
from app.blueprints.misc import misc_bp
from app.utils import read_config

app = Flask(__name__, template_folder="../../app/frontend/dist")


@app.route("/", methods=["GET"])
def main():
    """
        Return the index.html generated by Vue
    """
    return render_template("index.html")


@app.route("/<p>/<path:path>", methods=["GET"])
def get_file(p, path):
    """
        Return the frontend assets (css, js files, fonts etc.)
    """
    rp = "../../app/frontend/dist/{}".format(p)
    return send_from_directory(rp, path) if p in ["css", "fonts", "js", "img"] else redirect("/")


@app.errorhandler(404)
def page_not_found(e):
    return redirect("/")


# API Blueprints.
app.register_blueprint(network_bp, url_prefix='/api/network')
app.register_blueprint(capture_bp, url_prefix='/api/capture')
app.register_blueprint(device_bp, url_prefix='/api/device')
app.register_blueprint(analysis_bp, url_prefix='/api/analysis')
app.register_blueprint(save_bp, url_prefix='/api/save')
app.register_blueprint(misc_bp, url_prefix='/api/misc')

if __name__ == '__main__':
    port = read_config(("analysis", "http_default_port")) or 80
    if read_config(("frontend", "remote_access")):
        app.run(host="0.0.0.0", port=port)
    else:
        app.run(port=port)
