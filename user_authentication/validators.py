from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
# from django.utils.translation import gettext_lazy as _



'''
validate mobile number with length and characters
'''
def validate_mobile_no(value):
    if len(str(value)) != 10 and not str(value).isnumeric():
        raise ValidationError(_('Mobile number should contain exact 10 digits.'),code='invalid',params={'value': value},
        )
    