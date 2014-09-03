"""
Django models representing functions and descriptions.
"""
# related third party imports
from django.db import models

MAX_EXE_NAME_LENGTH = 255
EXE_DIGEST_SIZE_IN_BYTES = 32
FUNC_DIGEST_SIZE_IN_BYTES = 32
MAX_DATE_LENGTH = 50


class Function(models.Model):
    """
    A function, comprised of its attributes.
    """
    first_addr = models.PositiveIntegerField()
    exe_name = models.CharField(max_length=MAX_EXE_NAME_LENGTH)
    exe_md5 = models.CharField(max_length=EXE_DIGEST_SIZE_IN_BYTES)
    func_md5 = models.CharField(max_length=FUNC_DIGEST_SIZE_IN_BYTES)
    ins_num = models.PositiveIntegerField()

    filtering_attributes = models.TextField()
    matching_grade_attributes = models.TextField()
    primary_attributes = models.TextField()

    def __unicode__(self):
        return str(self.id)


class Description(models.Model):
    """
    A function, comprised of its attributes.
    Each Description is related to a single Function
    """
    function = models.ForeignKey(Function)
    # A json.sdump-ed string.
    func_name_and_cmts = models.TextField()
    date = models.CharField(max_length=MAX_DATE_LENGTH)

    def __unicode__(self):
        return str(self.id)
