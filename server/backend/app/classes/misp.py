#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from app import db
from app.db.models import MISPInst
from sqlalchemy.sql import exists
from app.definitions import definitions as defs
from urllib.parse import unquote
from flask import escape
from pymisp import PyMISP
import re
import time
import sys


class MISP(object):
    def __init__(self):
        return None

    @staticmethod
    def add_instance(misp_name, misp_url, misp_key, misp_verifycert):
        """
            Parse and add a MISP instance to the database.
            :return: status of the operation in JSON
        """

        sameinstances = db.session.query(MISPInst).filter(
            MISPInst.url == misp_url, MISPInst.apikey == misp_key)
        if sameinstances.count():
            return {"status": False,
                    "message": "This MISP instance already exists"}
        elif misp_name != "":
            if misp_url != "":
                if re.match(r"^(?:(?:http|https)://)", misp_url):
                    if misp_key != "":
                        added_on = int(time.time())
                        db.session.add(MISPInst(misp_name, escape(
                            misp_url), misp_key, misp_verifycert, added_on))
                        db.session.commit()
                        return {"status": True,
                                "message": "MISP instance added",
                                "name": escape(misp_name),
                                "url": escape(misp_url),
                                "apikey": escape(misp_key),
                                "verifycert": escape(misp_verifycert)}
                    else:
                        return {"status": False,
                                "message": "The key can't be empty"}
                else:
                    return {"status": False,
                            "message": "The url must begin with http:// or https://"}
            else:
                return {"status": False,
                        "message": "The url can't be empty"}
        else:
            return {"status": False,
                    "message": "The MISP instance name can't be empty"}

    @staticmethod
    def edit_instance(misp_id, misp_name, misp_url, misp_key, misp_verifycert):
        """
            Parse and edit the desired MISP instance.
            :return: status of the operation in JSON
        """
        misp = MISPInst.query.get(int(misp_id))
        otherinstances = db.session.query(MISPInst).filter(MISPInst.id != int(
            misp_id), MISPInst.url == misp_url, MISPInst.apikey == misp_key)
        if misp is None:
            return {"status": False,
                    "message": "Can't find the MISP instance"}
        if otherinstances.count() > 0:
            return {"status": False,
                    "message": "This MISP instance already exists"}
        elif misp_name != "":
            if misp_url != "":
                if re.match(r"^(?:(?:http|https)://)", misp_url):
                    if misp_key != "":
                        misp.name = misp_name
                        misp.url = misp_url
                        misp.apikey = misp_key
                        misp.verifycert = misp_verifycert
                        db.session.commit()
                        return {"status": True,
                                "message": "MISP instance edited"}
                    else:
                        return {"status": False,
                                "message": "The key can't be empty"}
                else:
                    return {"status": False,
                            "message": "The url must begin with http:// or https://"}
            else:
                return {"status": False,
                        "message": "The url can't be empty"}
        else:
            return {"status": False,
                    "message": "The MISP instance name can't be empty"}

    @staticmethod
    def delete_instance(misp_id):
        """
            Delete a MISP instance by its id in the database.
            :return: status of the operation in JSON
        """
        if db.session.query(exists().where(MISPInst.id == misp_id)).scalar():
            db.session.query(MISPInst).filter_by(id=misp_id).delete()
            db.session.commit()
            return {"status": True,
                    "message": "MISP instance deleted"}
        else:
            return {"status": False,
                    "message": "MISP instance not found"}

    @staticmethod
    def get_instances():
        """
            Get MISP instances from the database
            :return: generator of the records.
        """
        for misp in db.session.query(MISPInst).all():
            misp = misp.__dict__
            yield {"id": misp["id"],
                   "name": misp["name"],
                   "url": misp["url"],
                   "apikey": misp["apikey"],
                   "verifycert": misp["verifycert"]}

    @staticmethod
    def get_iocs(misp_id):
        """
            Get all IOCs from specific MISP instance
            /!\ Todo: NEED TO ADD LAST SYNCHRO DATE + page etc. stuff.
            :return: generator containing the IOCs.
        """
        misp = MISPInst.query.get(int(misp_id))
        if misp is not None:
            if misp.url and misp.apikey:
                # Connect to MISP instance and get network activity attributes.
                m = PyMISP(misp.url, misp.apikey, misp.verifycert)
                r = m.search("attributes", category="Network activity")

                for attr in r["Attribute"]:
                    if attr["type"] in ["ip-dst", "domain", "snort", "x509-fingerprint-sha1"]:

                        ioc = {"value": attr["value"],
                               "type": None,
                               "tag": "suspect",
                               "tlp": "white"}

                        # Deduce the IOC type.
                        if re.match(defs["iocs_types"][0]["regex"], attr["value"]):
                            ioc["type"] = "ipv4addr"
                        elif re.match(defs["iocs_types"][1]["regex"], attr["value"]):
                            ioc["type"] = "ipv6addr"
                        elif re.match(defs["iocs_types"][3]["regex"], attr["value"]):
                            ioc["type"] = "domain"
                        elif re.match(defs["iocs_types"][4]["regex"], attr["value"]):
                            ioc["type"] = "sha1cert"
                        elif "alert " in attr["value"][0:6]:
                            ioc["type"] = "snort"
                        else:
                            continue

                        if "Tag" in attr:
                            for tag in attr["Tag"]:
                                # Add the TLP of the IOC.
                                tlp = re.search(r"^(?:tlp:)(red|green|amber|white)", tag['name'].lower())
                                if tlp: ioc["tlp"] = tlp.group(1)

                                # Add possible tag.
                                if tag["name"].lower() in [t["tag"] for t in defs["iocs_tags"]]:
                                    ioc["tag"] = tag["name"].lower()
                        yield ioc
