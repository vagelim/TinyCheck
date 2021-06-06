#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, jsonify, Response, request
from app.decorators import require_header_token, require_get_token
from app.classes.mispobj import MISPObj

import json

misp_bp = Blueprint("misp", __name__)
misp = MISPObj()


@misp_bp.route('/add', methods=['POST'])
@require_header_token
def add ():
    """
        Parse and add a MISP instance to the database.
        :return: status of the operation in JSON
    """
    data = json.loads(request.data)
    instance = data["data"]["instance"]
    
    source = "backend"
    res = MISPObj.add(instance["name"], instance["url"], instance["key"], instance["ssl"], source)
    return jsonify(res)

@misp_bp.route('/delete/<misp_id>', methods=['GET'])
@require_header_token
def delete(misp_id):
    """
        Delete a MISP instance by its id to the database.
        :return: status of the operation in JSON
    """
    res = MISPObj.delete(misp_id)
    return jsonify(res)

@misp_bp.route('/get_all', methods=['GET'])
@require_header_token
def get_all():
    """
        Retreive a list of all MISP instances.
        :return: list of MISP instances in JSON.
    """
    res = MISPObj.get_all()
    return jsonify({"results": [i for i in res]})


@misp_bp.route('/get_iocs', methods=['POST'])
#@require_header_token
def get_iocs():
    """
        Retreive a list of all MISP instances.
        :return: list of MISP instances in JSON.
    """

    data = json.loads(request.data)
    data = data["data"]

    res = MISPObj.get_iocs(data["misp_id"], data["limit"], data["page"])
    print(res)
    return jsonify(res)


@misp_bp.route('/edit', methods=['POST'])
@require_header_token
def edit ():
    """
        Parse and edit the desired MISP instance.
        :return: status of the operation in JSON
    """
    data = json.loads(request.data)
    instance = data["data"]["instance"]
    print(instance)
    res = MISPObj.edit(instance["id"], instance["name"], instance["url"], instance["apikey"], instance["verifycert"])
    return jsonify(res)