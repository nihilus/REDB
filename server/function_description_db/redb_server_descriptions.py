"""
A description which was received from the server.
The server found it fitting for a specific function.
SuggestedDescription is loaded into a LocalDescription.
The data-type is agreed upon by both the client and the server.
"""


class SuggestedDecsription:
    """
    A description which was received from the server. The server found it
    fitting for a specific function. SuggestedDescription is loaded into a
    LocalDescription. The data-type is agreed upon by both the client and the
    server.
    to_dict and from_dict functions are used when sending and recieving data
    from server. No SuggestedDescription objects are really sent from the
    server, only these dictionaries, jsoned (like pickeled).
    """
    def __init__(self, \
                 func_name_and_cmts=None, \
                 matching_grade=None, \
                 can_be_embedded=None, \
                 date=None):
        self.func_name_and_cmts = func_name_and_cmts
        self.matching_grade = matching_grade
        self.can_be_embedded = can_be_embedded
        self.date = date

    def to_dict(self):
        sugg_dict = {}
        sugg_dict["func_name_and_cmts"] = self.func_name_and_cmts
        sugg_dict["matching_grade"] = self.matching_grade
        sugg_dict["can_be_embedded"] = self.can_be_embedded
        sugg_dict["date"] = self.date
        return sugg_dict

    def from_dict(self, sugg_dict):
        self.func_name_and_cmts = sugg_dict["func_name_and_cmts"]
        self.matching_grade = sugg_dict["matching_grade"]
        self.can_be_embedded = sugg_dict["can_be_embedded"]
        self.date = sugg_dict["date"]
