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
        logger.info("Found empty mail address in django. Deleting")
        Empty_Email.delete()



    logger.info("EMAIL: " + email)
    if user:
        logger.info("user is an object")
        logger.info("user.username: " + user.username)
        logger.info("user.name: " + user.name)
        logger.info("user.email: " + user.email)
    else:
        logger.info("not user")


    Created_Mail, Success = UserEmail.objects.get_or_create(user=user, email=email)

    if Success:
        logger.info("Success")
    else:
        logger.info("failed")

    if Created_Mail:
        logger.info("Created_Mail")
    else:
        logger.info("NOT Created_Mail") 

    
        

    return True


def update_org_membership(user_model, user_role):
    user_organizations = OrganizationMember.objects.filter(user=user_model)
    if user_organizations == None or len(user_organizations) == 0:
        logger.info("User is not in any organisation.")

        if not settings.AUTH_LDAP_DEFAULT_SENTRY_ORGANIZATION:
            logger.error("No default organization in ldap config.")
            return False

        target_organizations = Organization.objects.filter(slug=settings.AUTH_LDAP_DEFAULT_SENTRY_ORGANIZATION)
        if not target_organizations or len(target_organizations) < 1:
            logger.error("Did not find the organization from the ldap config.")
            return False

        organization_result = OrganizationMember.objects.create(
            organization=target_organizations[0],
            user=user_model,
            role=user_role,
            has_global_access=getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_GLOBAL_ACCESS', False),
            flags=getattr(OrganizationMember.flags, u'sso:linked')
        )

        if organization_result:
            logger.info("Added user to organization")
            return True
        else:
            logger.error("Failed to add user to organization")
            return False

    logger.info("User is already in organisation. Updating settings")
    user_organizations[0].role = user_role
    user_organizations[0].has_global_access = getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_GLOBAL_ACCESS', False)
    user_organizations[0].save()



class SentryLdapBackend(LDAPBackend):
    def get_or_build_user(self, username, ldap_user):

        logger.info("Start")

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
            logger.warning("Did not find a user model")
            return user_model

        assign_mail_success = assign_mail_to_user(ldap_user, user_model[0])
        if not assign_mail_success:
            logger.warning("Unable to assign mail address to user")
            return user_model

        user_model[0].is_managed = True

        if getattr(settings, 'AUTH_LDAP_SENTRY_SUBSCRIBE_BY_DEFAULT', True):
            UserOption.objects.set_value(user=user_model[0], project=None, key='subscribe_by_default', value='1')
        else:
            UserOption.objects.set_value(user=user_model[0], project=None, key='subscribe_by_default', value='0')
        user_role = get_sentry_role_from_group_Mapping(ldap_user.group_names)

        update_org_membership(user_model[0], user_role)

        logger.info("End")
        return user_model
