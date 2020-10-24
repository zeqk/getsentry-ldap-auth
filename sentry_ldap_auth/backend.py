from __future__ import absolute_import
from django_auth_ldap.backend import LDAPBackend
from django.conf import settings
from django.db.models import Q
from sentry.models import (
    Organization,
    OrganizationMember,
    UserOption,
)


import logging
logger = logging.getLogger("sentry-ldap-auth")


class SentryLdapBackend(LDAPBackend):
    def get_or_build_user(self, username, ldap_user):
        
        logger.info("get_or_build_user - Start")
        logger.info("username:" + username)
        logger.info("ldap_user:" + str(ldap_user))

        if not username:
            logger.warning("Username Missing")
            pass

        if not ldap_user:
            logger.warning("LDAP User Missing")
            pass

        LDAP_USERNAME_FIELD = getattr(settings, 'AUTH_LDAP_SENTRY_USERNAME_FIELD', '')
        if not LDAP_USERNAME_FIELD: 
            logger.warning("AUTH_LDAP_SENTRY_USERNAME_FIELD Missing or Empty")
            pass

        if not LDAP_USERNAME_FIELD in ldap_user.attrs:
            logger.warning("AUTH_LDAP_SENTRY_USERNAME_FIELD does not exist in the LDAP User")
            pass

        username = ldap_user.attrs[LDAP_USERNAME_FIELD]
        logger.info("new username: " + username)
        
        if isinstance(username, (list, tuple)):
            logger.info("isinstance: " + username[0])
            username = username[0]
        
        
        
        model = super(SentryLdapBackend, self).get_or_build_user(username, ldap_user)

        return model
