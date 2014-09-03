"""
Description data types.
"""

# related third party imports
import idaapi

# local application/library specific imports
import redb_client_utils


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
    def __init__(self,
                 func_name_and_cmts=None,
                 matching_grade=None,
                 can_be_embedded=None,
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


class LocalDescription:
    """
    A description for a specific local function. It is initiated either by
    loading a SuggestedDescription or by loading the user's own description.
    Each LocalDescription can be shown on screen. A LocalDescription initiated
    by loading a SuggestedDescription can be merged into the user's description
    if it can be embedded.
    """
    def __init__(self, addr):
        self._first_addr = idaapi.get_func(addr).startEA
        self._is_loaded = False
        self._is_user_description = None
        self._func_name_and_cmts = None

        # Next fields only relevant if the description is a suggested one.
        self._can_be_embedded = None
        self._MatchingGrade = None
        self._date = None

    def load_suggested(self, suggested_desc):
        """
        Load a SuggestedDescription.
        """
        if self._is_loaded:
            print "REDB: Description already loaded!"
        else:
            self._func_name_and_cmts = suggested_desc.func_name_and_cmts
            self._can_be_embedded = suggested_desc.can_be_embedded
            self._MatchingGrade = suggested_desc.matching_grade
            self._date = suggested_desc.date
            self._is_user_description = False
            self._is_loaded = True
            print "REDB: Suggested description loaded."

    def load_users(self):
        """
        Load the user's description, or save changes.
        """
        if (self._is_user_description is None) or self._is_user_description:
            # If LocalDescription is not loaded, or if saving changes.
            self._func_name_and_cmts = \
                redb_client_utils.Extract(self._first_addr).extract_all()
            self._can_be_embedded = True
            if self._is_loaded:
                print "REDB: Changes in user's description saved."
            else:
                self._is_loaded = True
                self._is_user_description = True
        else:
            print ("REDB: Changes made to descriptions which aren't your" +
                   " own will not be saved!")

    def show_desc(self, index=None, outof=None):
        """
        If self.can_be_embedded embed each comments in it's place.
        O.w. embed short version in the beginning of the function.
        """
        if self._can_be_embedded or self._is_user_description:
            redb_client_utils.Embed(self._first_addr).\
                embed_all(self._func_name_and_cmts)
        else:
            redb_client_utils.Embed(self._first_addr).\
                embed_short(self._func_name_and_cmts)

        self._add_tag(index, outof)

        idaapi.refresh_idaview_anyway()
        if not self._is_user_description:
            print ("REDB: Showing public description " + str(index) +
                   "/" + str(outof))
        else:
            print "REDB: Showing user's description."

    def remove_desc(self):
        self._remove_tag()
        if self._is_user_description:
            self.load_users()
        redb_client_utils.RemoveFuncCmnts(self._first_addr)

    def _add_tag(self, index=None, outof=None):
        redb_client_utils.Tag(self._first_addr).\
            add_tag(self._is_user_description,
                    index, outof,
                    self._MatchingGrade)

    def _remove_tag(self):
        redb_client_utils.Tag(self._first_addr).remove_tag()

    def merge_into_users(self):
        """
        Merge a LocalDescription initiated by loading a
        SuggestedDescription into the user's.
        """
        if not self._is_user_description:
            if self._func_name_and_cmts == None:
                print "REDB: Can't merge, load description first!"
            else:
                redb_client_utils.Embed(self._first_addr).\
                    merge_all(self._func_name_and_cmts)
        else:
            print "REDB: Can't merge, this IS your Description!"
