from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IHttpListener
import json
import Pyro4
import re
import array


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):

        # Set the name of the extension
        callbacks.setExtensionName("Auto fill sign")

        # Save references to useful objects
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        # Register ourselves as an HttpListener, in this way all requests and
        # responses will be forwarded to us
        callbacks.registerHttpListener(self)

    def get_sign(self, bodyString):
        uri = 'PYRO:BridaServicePyro@localhost:9999'
        pp = Pyro4.Proxy(uri)
        args = []
        if len(bodyString) > 0:
            args.append(bodyString)
        else:
            args.append('')
        _retvalue = pp.callexportfunction('getsign', args)
        pp._pyroRelease()
        return _retvalue

    def find_header(self, findstr, oldheaders):
        _find_flag = False
        for header_string in oldheaders:
            if findstr in header_string:
                _find_flag = True
                break

        return _find_flag

    def gen_headers(self, oldheaders, sign):

        _newheaders = oldheaders
        _signature_str = ""
        _timestamp_str = ""

        _value_list = sign.split(',')
        if len(_value_list) >= 1:
            _signature_str = _value_list[0]
            _timestamp_str = _value_list[1]

        # gen new headers
        _newheaders.append(_signature_str)
        _newheaders.append(_timestamp_str)

        return _newheaders

    def check_Flag(self, toolFlag):
         # only support Repeater and INTRUDER
        _f = False
        if ((toolFlag == 64) or (toolFlag == 32)):
            _f = True
        return _f

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if messageIsRequest and self.check_Flag(toolFlag):

            # Get request bytes
            request = messageInfo.getRequest()
            # Get a IRequestInfo object, useful to work with the request
            analyzedRequest = self.helpers.analyzeRequest(request)
            headers = list(analyzedRequest.getHeaders())
            bodyOffset = int(analyzedRequest.getBodyOffset())

            body = request[bodyOffset:]
            bodyString = "".join(map(chr, body))

            if self.find_header('Host: xxxx.xxxx.com', headers):

                # get sign from brida
                _sign = self.get_sign(bodyString)
                _newheaders = self.gen_headers(headers, _sign)

                if len(_newheaders) > 0:
                    _newRequest = self.helpers.buildHttpMessage(
                        _newheaders, body)
                    messageInfo.setRequest(_newRequest)
            pass
