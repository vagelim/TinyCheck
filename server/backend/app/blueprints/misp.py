#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, jsonify, Response, request
from app.decorators import require_header_token, require_get_token
from app.classes.misp import MISP

import json

misp_bp = Blueprint("misp", __name__)
misp = MISP()


@misp_bp.route('/add', methods=['POST'])
@require_header_token
def add_instance():
    """
        Parse and add a MISP instance to the database.
        :return: status of the operation in JSON
    """
    data = json.loads(request.data)
    instance = data["data"]["instance"]

    res = MISP.add_instance(instance["name"], instance["url"],
                   instance["key"], instance["ssl"])
    return jsonify(res)


@misp_bp.route('/delete/<misp_id>', methods=['GET'])
@require_header_token
def delete_instance(misp_id):
    """
        Delete a MISP instance by its id to the database.
        :return: status of the operation in JSON
    """
    res = MISP.delete_instance(misp_id)
    return jsonify(res)


@misp_bp.route('/get_all', methods=['GET'])
# @require_header_token
def get_all():
    """
        Retreive a list of all MISP instances.
        :return: list of MISP instances in JSON.
    """
    res = MISP().get_instances()
    return jsonify({"results": [i for i in res]})


@misp_bp.route('/get_iocs', methods=['POST'])
# @require_header_token
def get_iocs():
    """
        Retreive a list of all MISP instances.
        :return: list of MISP instances in JSON.
    """

    data = json.loads(request.data)
    data = data["data"]

    res = MISP.get_iocs(data["misp_id"],
                        data["limit"],
                        data["page"])
    return jsonify(res)
