from __future__ import absolute_import
from django_auth_ldap.backend import LDAPBackend
from django.conf import settings
from django.db.models import Q
from sentry.models import (Organization, OrganizationMember, UserOption, UserEmail)


import logging
logger = logging.getLogger("sentry-ldap-auth")


def get_sentry_role_from_group_Mapping(group_names):
    CONFIG_DEFAULT_ROLE = getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_ROLE_TYPE', None)
    
    CONFIG_ROLE_MAPPING = getattr(settings, 'AUTH_LDAP_SENTRY_GROUP_ROLE_MAPPING', None)
    if not group_names or not CONFIG_ROLE_MAPPING:
        if CONFIG_DEFAULT_ROLE:
            logger.debug("User is not in any known group. Using default from config")
            return CONFIG_DEFAULT_ROLE
        else:
            logger.debug("User is not in any known group and no default specified")
            return None

    applicable_roles = [role for role, groups in CONFIG_ROLE_MAPPING.items() if group_names.intersection(groups)]
    if not applicable_roles:
        if CONFIG_DEFAULT_ROLE:
            logger.debug("User has no match with group mapping. Using default from config")
            return CONFIG_DEFAULT_ROLE
        else:
            logger.debug("User has no match with group mapping and no default specified")
            return None

    highest_role = [role for role in ['member','admin','manager','owner'] if role in applicable_roles][-1]
    if not highest_role:
        if CONFIG_DEFAULT_ROLE:
            logger.debug("User has no match with sentry group names. Using default from config")
            return CONFIG_DEFAULT_ROLE
        else:
            logger.debug("User has no match with sentry group names and no default specified")
            return None

    return highest_role



def assign_mail_to_user(ldap_user, user):
    if 'mail' in ldap_user.attrs:
        email = ldap_user.attrs.get('mail')[0]
    elif hasattr(settings, 'AUTH_LDAP_DEFAULT_EMAIL_DOMAIN'):
        email = username + '@' + settings.AUTH_LDAP_DEFAULT_EMAIL_DOMAIN
    else:
        email = ''

    Empty_Email = UserEmail.objects.filter(Q(email='') | Q(email=' '), user=user)
    if Empty_Email:
        logger.info("Found empty EMail address in django. Deleting")
        Empty_Email.delete()

    logger.info("EMAIL: " + email)
    Created_Mail, Success = UserEmail.objects.get_or_create(user=user, email=email)
    if Success:
        logger.info("Success")
    else:
        logger.info("failed")
    
    return True



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

        assign_mail_success = assign_mail_to_user(ldap_user, user_model[0])
        if not assign_mail_success: #M aybe this is boardline wrong i the get or create can return false?
            logger.warning("Unable to assign mail address to user")
            return user_model

        user_model[0].is_managed = True
        user_global_access = getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_GLOBAL_ACCESS', False)
        user_role = get_sentry_role_from_group_Mapping(ldap_user.group_names)

        
        
        user_organizations = OrganizationMember.objects.filter(user=user_model[0])
        logger.info("OrganizationMember: " + str(len(user_organizations)))
        
        if user_organizations == None or len(user_organizations) == 0:
            logger.debug("User is not in any organisation. Assigning")
        else:
            logger.info("User is already in organisation. Updating settings")
        
        
        
        


        logger.info("get_or_build_user - End")

        return user_model
