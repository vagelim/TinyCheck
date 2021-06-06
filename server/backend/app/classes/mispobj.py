#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from app import db
from app.db.models import MISPInst
from sqlalchemy.sql import exists
from app.definitions import definitions
from urllib.parse import unquote
from flask import escape
from pymisp import PyMISP
import re
import time
import sys


class MISPObj(object):
    def __init__(self):
        return None

    @staticmethod
    def add(misp_name, misp_url, misp_key, misp_verifycert, source):
        """
            Parse and add a MISP"instance to the database.
            :return: status of the operation in JSON
        """
        
        sameinstances = db.session.query(MISPInst).filter(MISPInst.url == misp_url, MISPInst.apikey == misp_key)
        if sameinstances.count() > 0:
            return {"status": False,
                    "message": "This MISP instance already exists",
                    "name": escape(misp_name),
                    "url": escape(misp_url),
                    "apikey": escape(misp_key),
                    "verifycert": escape(misp_verifycert)}
        elif misp_name != "":          
            if misp_url != "":               
                if re.match(r"^(?:(?:http|https)://)", misp_url):
                    if misp_key != "":
                        added_on = int(time.time())
                        db.session.add(MISPInst(misp_name, escape(misp_url), misp_key, misp_verifycert, source, added_on))
                        db.session.commit()
                        return {"status": True,
                            "message": "MISP instance added",
                            "name": escape(misp_name),
                            "url": escape(misp_url),
                            "apikey": escape(misp_key),
                            "verifycert": escape(misp_verifycert)}
                    else:
                        return {"status": False,
                        "message": "The key can't be empty",
                        "name": escape(misp_name),
                        "url": escape(misp_url),
                        "apikey": "",
                        "verifycert": escape(misp_verifycert)}
                else:
                    return {"status": False,
                        "message": "The url must begin with http:// or https://",
                        "name": escape(misp_name),
                        "url": escape(misp_url),
                        "apikey": escape(misp_key),
                        "verifycert": escape(misp_verifycert)}
            else:
                return {"status": False,
                        "message": "The url can't be empty",
                        "name": escape(misp_name),
                        "url": "",
                        "apikey": escape(misp_key),
                        "verifycert": escape(misp_verifycert)}
        else:
            return {"status": False,
                    "message": "The MISP instance name can't be empty",
                    "name":"",
                    "url": escape(misp_url),
                    "apikey": escape(misp_key),
                    "verifycert": escape(misp_verifycert)}

    @staticmethod
    def edit(misp_id, misp_name, misp_url, misp_key, misp_verifycert):
        """
            Parse and edit the desired MISP instance.
            :return: status of the operation in JSON
        """
        mispinstance = MISPInst.query.get(int(misp_id))
        otherinstances = db.session.query(MISPInst).filter(MISPInst.id != int(misp_id), MISPInst.url == misp_url, MISPInst.apikey == misp_key)
        if mispinstance is None:                                                                                                                                            
            return {"status": False,
                    "message": "Can't find the MISP instance"}
        if otherinstances.count() > 0:
            return {"status": False,
                    "message": "This MISP instance already exists",
                    "name": escape(misp_name),
                    "url": escape(misp_url),
                    "apikey": escape(misp_key),
                    "verifycert": escape(misp_verifycert)}
        elif misp_name != "":          
            if misp_url != "":               
                if re.match(r"^(?:(?:http|https)://)", misp_url):
                    if misp_key != "":
                        mispinstance.name = misp_name
                        mispinstance.url = misp_url
                        mispinstance.apikey = misp_key
                        mispinstance.verifycert = misp_verifycert
                        db.session.commit()
                        return {"status": True,
                            "message": "MISP instance edited",
                            "name": escape(misp_name),
                            "url": escape(misp_url),
                            "apikey": escape(misp_key),
                            "verifycert": escape(misp_verifycert)}
                    else:
                        return {"status": False,
                        "message": "The key can't be empty",
                        "name": escape(misp_name),
                        "url": escape(misp_url),
                        "apikey": "",
                        "verifycert": escape(misp_verifycert)}
                else:
                    return {"status": False,
                        "message": "The url must begin with http:// or https://",
                        "name": escape(misp_name),
                        "url": escape(misp_url),
                        "apikey": escape(misp_key),
                        "verifycert": escape(misp_verifycert)}
            else:
                return {"status": False,
                        "message": "The url can't be empty",
                        "name": escape(misp_name),
                        "url": "",
                        "apikey": escape(misp_key),
                        "verifycert": escape(misp_verifycert)}
        else:
            return {"status": False,
                    "message": "The MISP instance name can't be empty",
                    "name":"",
                    "url": escape(misp_url),
                    "apikey": escape(misp_key),
                    "verifycert": escape(misp_verifycert)}


    @staticmethod
    def delete(misp_id):
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
    def get_all():
        """
            Get all MISP instances from the database
            :return: generator of the records.
        """
        for mispinstance in db.session.query(MISPInst).all():
            mispinstance = mispinstance.__dict__
            yield {"id": mispinstance["id"],
                   "name": mispinstance["name"],
                   "url": mispinstance["url"],
                   "apikey": mispinstance["apikey"],
                   "verifycert": mispinstance["verifycert"]}

    @staticmethod
    def get_iocs(misp_id, limit, page):
        """
            Get all IOCs from the desired MISP instance
            :return: generator of the records.
        """
        mispinstance = MISPInst.query.get(int(misp_id))
        if mispinstance is not None:
            if mispinstance.url != "":
                if mispinstance.apikey != "":
                    try:
                        # Connects to the desired MISP instance
                        mispinstance = PyMISP(mispinstance.url, mispinstance.apikey, mispinstance.verifycert)
                        
                        # Retreives the attributes (or IOCs) that are supported by Tinycheck
                        attributes = mispinstance.search('attributes', category='Network activity', limit=limit, page=page, metadata=True)
                        

                        if 'Attribute' in attributes:
                            iocs = []
                            for attribute in attributes['Attribute']:
                                #print(attribute)
                                if 'value' in attribute and attribute['value'] != '':
                                    # We have a valid value
                                    ioc_value = attribute['value']
                                    ioc_type = "unknown"
                                    ioc_tag = "No tag"
                                    ioc_tlp = "white"
                                    isFirstTag = True
                                    
                                    if 'Tag' in attribute:
                                        # We have some tags
                                        #print (attribute['Tag'])
                                        for tag in attribute['Tag']:
                                            tlp = re.search(r"^(?:tlp:)(red|green|amber|white)", tag['name'])
                                            if tlp:
                                                # The current tag is the tlp level
                                                ioc_tlp = tlp.group(1)
                                                #print(ioc_tlp)
                                            elif isFirstTag:
                                                # It is the first retreived tag that is not a tlp 
                                                isFirstTag = False
                                                ioc_tag = tag['name']
                                            else:
                                                # It is another tag and not the first one
                                                ioc_tag += ", " + tag['name']
                                                
                                    ioc = { "value": ioc_value,
                                            "type": ioc_type,
                                            "tag": ioc_tag,
                                            "tlp": ioc_tlp }
                                    iocs.append(ioc)
                            return { "status":True,
                                     "results": iocs}
                        else:
                            return { "status":False,
                                     "message":"No valid IOCs found."}
                    except TypeError as error:
                        print (error)
                        pass
                    except:
                        print("An exception has been raised: ", sys.exc_info()[0])
                        pass
                else:
                    {"status": False,
                     "message": "The api key can't be empty"}       
            else:
                return {"status": False,
                        "message": "The url can't be empty"}
        else:
            return {"status": False,
                    "message": "Unknown MISP instance."}