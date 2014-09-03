"""
Methods and utilities required for communicating with the server.
"""

# related third party imports
import simplejson as json
from redb_client_utils import _decode_dict


#==============================================================================
# Taken from http://code.activestate.com
#==============================================================================
import httplib
import mimetypes
import mimetools
import redb_client_utils


def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to
    be uploaded as files. Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTP(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()  # @UnusedVariable
    return_data = h.file.read()
    # DEBUG Only:
    # h2 = open("c:\\htm.html","wb")
    # h2.write(return_data)
    # h2.close()
    return return_data


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files. Returns (content_type, body) ready for httplib.HTTP
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


#==============================================================================
# Submit/Request Functions
#==============================================================================
def send_request(request):
    """
    Given a jsoned Request instance, sends it. Returns a Response instance.
    """
    response = None
    parse_config = redb_client_utils._parse_config_file()

    try:
        response = Response()
        response.from_json(post_multipart(parse_config.host,
                                         "/request/",
                                         [],
                                         [("pickled_request",
                                           "pickled_request",
                                           request)]
                                         ))

    except:
        print "REDB: An error occurred while requesting descriptions!"
        response = None

    return response

"""
Given an address of a server and an instance of Submit,
it send the Submit instance to the server.
"""


def send_submit(submit):
    """
    Given a jsoned Submit instance, sends it.
    """
    parse_config = redb_client_utils._parse_config_file()

    retval = post_multipart(parse_config.host,
                            "/submit/",
                            [],
                            [("pickled_submit",
                              "pickled_submit",
                              submit)]
                            )
    # handle response
    if retval:
        print "REDB: Uploaded description to server successfully."
    else:
        print "REDB: An error occurred while submitting descriptions!"


#==============================================================================
# Communication Data Types
#==============================================================================
class Request:
    """
    A request for descriptions for a specific function.
    """
    def __init__(self, \
                 primary_attributes=None,
                 filtering_attributes=None,
                 matching_grade_attributes=None,
                 num_of_returned_comments=None):

        self.primary_attributes = primary_attributes
        self.filtering_attributes = filtering_attributes
        self.matching_grade_attributes = matching_grade_attributes
        self.num_of_returned_comments = num_of_returned_comments

    def to_json(self):
        req_dict = {}
        req_dict["primary_attributes"] = self.primary_attributes
        req_dict["filtering_attributes"] = self.filtering_attributes
        req_dict["matching_grade_attributes"] = self.matching_grade_attributes
        req_dict["num_of_returned_comments"] = self.num_of_returned_comments
        return json.dumps(req_dict)

    def from_json(self, json_obj):
        req_dict = json.loads(json_obj, object_hook=_decode_dict)
        self.primary_attributes = req_dict["primary_attributes"]
        self.filtering_attributes = req_dict["filtering_attributes"]
        self.matching_grade_attributes = req_dict["matching_grade_attributes"]
        self.num_of_returned_comments = req_dict["num_of_returned_comments"]


class Response:
    """
    A response from the server to a request.
    """
    def __init__(self, \
                  suggested_descriptions_list=None):

        self.suggested_descriptions = suggested_descriptions_list

    def to_json(self):
        return json.dumps(self.suggested_descriptions)

    def from_json(self, json_obj):
        self.suggested_descriptions = json.loads(json_obj,
                                                 object_hook=_decode_dict)


class Submit:
    """
    A Submit includes data gathered about a specific function.
    """
    def __init__(self, \
                 primary_attributes=None,
                 filtering_attributes=None,
                 matching_grade_attributes=None,
                 comments_and_name=None):

        self.primary_attributes = primary_attributes
        self.filtering_attributes = filtering_attributes
        self.matching_grade_attributes = matching_grade_attributes
        self.comments_and_name = comments_and_name

    def to_json(self):
        sub_dict = {}
        sub_dict["primary_attributes"] = self.primary_attributes
        sub_dict["filtering_attributes"] = self.filtering_attributes
        sub_dict["matching_grade_attributes"] = self.matching_grade_attributes
        sub_dict["comments_and_name"] = self.comments_and_name
        return json.dumps(sub_dict)

    def from_json(self, json_obj):
        sub_dict = json.loads(json_obj, object_hook=_decode_dict)
        self.primary_attributes = sub_dict["primary_attributes"]
        self.filtering_attributes = sub_dict["filtering_attributes"]
        self.matching_grade_attributes = sub_dict["matching_grade_attributes"]
        self.comments_and_name = sub_dict["comments_and_name"]
