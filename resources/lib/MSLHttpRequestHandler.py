# -*- coding: utf-8 -*-
# Author: trummerjo
# Module: MSLHttpRequestHandler
# Created on: 26.01.2017
# License: MIT https://goo.gl/5bMj3H

"""Handles & translates requests from Inputstream to Netflix"""

import base64
import BaseHTTPServer
from urlparse import urlparse, parse_qs
from resources.lib.MSL import MSL as Msl
from resources.lib.KodiHelper import KodiHelper
from SocketServer import TCPServer

KODI_HELPER = KodiHelper()

class MSLHttpRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """Handles & translates requests from Inputstream to Netflix"""

    # pylint: disable=invalid-name
    def do_HEAD(self):
        """Answers head requests with a success code"""
        self.send_response(200)

    # pylint: disable=invalid-name
    def do_POST(self):
        """Loads the licence for the requested resource"""
        length = int(self.headers.get('content-length'))
        post = self.rfile.read(length)
        print post
        data = post.split('!')
        if len(data) is 2:
            challenge = data[0]
            sid = base64.standard_b64decode(data[1])
            b64license = self.server.MSL.get_license(challenge, sid)
            if b64license is not '':
                self.send_response(200)
                self.end_headers()
                self.wfile.write(base64.standard_b64decode(b64license))
                self.finish()
            else:
                KODI_HELPER.log(msg='Error getting License')
                self.send_response(400)
        else:
            KODI_HELPER.log(msg='Error in License Request')
            self.send_response(400)

    # pylint: disable=invalid-name
    def do_GET(self):
        """Loads the XML manifest for the requested resource"""
        url = urlparse(self.path)
        params = parse_qs(url.query)
        if 'id' not in params:
            self.send_response(400, 'No id')
        else:
            # Get the manifest with the given id
            data = self.server.MSL.load_manifest(int(params['id'][0]))
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(data)

    def log_message(self, *args):
        """Disable the BaseHTTPServer Log"""
        pass

##################################

class MSLTCPServer(TCPServer):

    def __init__(self, server_address):
        KODI_HELPER.log(msg='Constructing MSLTCPServer')
        self.MSL = Msl(kodi_helper=KODI_HELPER)
        TCPServer.__init__(self, server_address, MSLHttpRequestHandler)
