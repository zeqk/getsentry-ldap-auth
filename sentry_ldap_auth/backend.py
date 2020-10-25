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


def get_sentry_role_from_group_Mapping(group_names):
    CONFIG_ROLE_MAPPING = getattr(settings, 'AUTH_LDAP_SENTRY_GROUP_ROLE_MAPPING', None)
    if not group_names or not CONFIG_ROLE_MAPPING:
        logger.debug("User is not in any known group")
        return None

    applicable_roles = [role for role, groups in CONFIG_ROLE_MAPPING.items() if group_names.intersection(groups)]
    if not applicable_roles:
        logger.debug("User has no match with group mapping")
        return None

    highest_role = [role for role in ['member','admin','manager','owner'] if role in applicable_roles][-1]
    return highest_role



class SentryLdapBackend(LDAPBackend):
    def get_or_build_user(self, username, ldap_user):

        logger.info("get_or_build_user - Start")

        if not username:
            logger.warning("Username Missing")
            pass

        if not ldap_user:
            logger.warning("LDAP User Missing")
            pass

        CONFIG_USERNAME_FIELD = getattr(settings, 'AUTH_LDAP_SENTRY_USERNAME_FIELD', '')
        if not CONFIG_USERNAME_FIELD: 
            logger.warning("AUTH_LDAP_SENTRY_USERNAME_FIELD Missing or Empty")
            pass

        if not CONFIG_USERNAME_FIELD in ldap_user.attrs:
            logger.warning("AUTH_LDAP_SENTRY_USERNAME_FIELD does not exist in the LDAP User")
            pass

        username = ldap_user.attrs[CONFIG_USERNAME_FIELD]
        if isinstance(username, (list, tuple)):
            username = username[0]

        user_model = super(SentryLdapBackend, self).get_or_build_user(username, ldap_user)
        if len(user_model) < 1:
            logger.warning("Did not find a user_model")
            return user_model

        user = user_model[0]
        user.is_managed = True
        
        if user.is_managed:
            logger.info("is managed")
        else:
            logger.info("NOT managed")

        user_global_access = getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_GLOBAL_ACCESS', False)
        if user_global_access:
            logger.info("HAS GLOBAL ACCESS")
        else:
            logger.info("NO GLOBAL ACCESS")
            
        user_role = get_sentry_role_from_group_Mapping(ldap_user.group_names)
        
        logger.info("user_role: " + user_role)
        if not user_role:
            logger.info("default user_role")
            user_role = getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_ROLE_TYPE', None)


        
        
        logger.info("get_or_build_user - End")

        return user_model
