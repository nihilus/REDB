"""
Tools required for the Lab to communicate with the server on its own.
"""

import json
import httplib
import mimetypes
import mimetools

##########################################
# Taken from http://code.activestate.com #
##########################################


def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files. Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTP(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()  # @UnusedVariable
    a = h.file.read()
    return a


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files. Return (content_type, body) ready for httplib.HTTP
    instance.
    """
    BOUNDARY = mimetools.choose_boundary()
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' %
                 (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


def send_compare(host, compare):
    """
    Receives a comparison json-ed request and passes it on to the server,
    returns the results.
    """
    print "DEBUG: send_compare STARTED"

    compare_response = None

    # post compare
    try:
        compare_response = CompareResponse()
        compare_response.from_json(post_multipart(host, "/compare/", [],
                                                 [("compare", "compare",
                                                   compare)]))
    except:
        print "REDB: An error occurred while comparing!"
        compare_response = None
    print "DEBUG: send_compare FINISHED\n"

    return compare_response


class Compare:
    """
    A comparison request.
    Compare functions_from_exe_1 from exe_name_1 with functions_from_exe_2
    from exe_name_2.
    """
    def __init__(self, \
                 exe_name_1=None, \
                 functions_from_exe_1=None, \
                 exe_name_2=None, \
                 functions_from_exe_2=None, \
                 attr_list=None
                 ):

        self.exe_name_1 = exe_name_1
        self.functions_from_exe_1 = functions_from_exe_1
        self.exe_name_2 = exe_name_2
        self.functions_from_exe_2 = functions_from_exe_2
        self.attr_list = attr_list

    def to_json(self):
        cmp_dict = {}
        cmp_dict["exe_name_1"] = self.exe_name_1
        cmp_dict["functions_from_exe_1"] = self.functions_from_exe_1
        cmp_dict["exe_name_2"] = self.exe_name_2
        cmp_dict["functions_from_exe_2"] = self.functions_from_exe_2
        cmp_dict["attr_list"] = self.attr_list
        return json.dumps(cmp_dict)

    def from_json(self, json_obj):
        cmp_dict = json.loads(json_obj, object_hook=_decode_dict)
        self.exe_name_1 = cmp_dict["exe_name_1"]
        self.functions_from_exe_1 = cmp_dict["functions_from_exe_1"]
        self.exe_name_2 = cmp_dict["exe_name_2"]
        self.functions_from_exe_2 = cmp_dict["functions_from_exe_2"]
        self.attr_list = cmp_dict["attr_list"]


class CompareResponse:
    """
    Comparison results.
    """
    def __init__(self, \
                  compare_results=None):

        self.compare_results = compare_results

    def to_json(self):
        return json.dumps(self.compare_results)

    def from_json(self, json_obj):
        self.compare_results = json.loads(json_obj, object_hook=_decode_dict)


def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv
