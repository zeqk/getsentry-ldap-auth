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




def _get_effective_sentry_role(group_names):
    role_priority_order = [
        'member',
        'admin',
        'manager',
        'owner',
    ]

    role_mapping = getattr(settings, 'AUTH_LDAP_SENTRY_GROUP_ROLE_MAPPING', None)

    if not group_names or not role_mapping:
        return None

    applicable_roles = [role for role, groups in role_mapping.items() if group_names.intersection(groups)]

    if not applicable_roles:
        return None

    highest_role = [role for role in role_priority_order if role in applicable_roles][-1]
    return highest_role


class SentryLdapBackend(LDAPBackend):
    def get_or_build_user(self, username, ldap_user):
        logger.info("get_or_build_user - Start")
        username_field = getattr(settings, 'AUTH_LDAP_SENTRY_USERNAME_FIELD', '')
        if username_field:
            # pull the username out of the ldap_user info
            if ldap_user and username_field in ldap_user.attrs:
                username = ldap_user.attrs[username_field]
                if isinstance(username, (list, tuple)):
                    username = username[0]
        model = super(SentryLdapBackend, self).get_or_build_user(username, ldap_user)

        if len(model) < 1:
            return model

        user = model[0]

        user.is_managed = True
        # Add the user email address
        try:
            from sentry.models import (UserEmail)
        except ImportError:
            pass
        else:
            if 'mail' in ldap_user.attrs:
                email = ldap_user.attrs.get('mail')[0]
            elif not hasattr(settings, 'AUTH_LDAP_DEFAULT_EMAIL_DOMAIN'):
                email = ''
            else:
                email = username + '@' + settings.AUTH_LDAP_DEFAULT_EMAIL_DOMAIN

            # django-auth-ldap may have accidentally created an empty email address
            logger.info("HIT 2 D")
            
            UserEmail.objects.filter(Q(email='') | Q(email=' '), user=user).delete()
            if email:
                logger.info("HIT 2 E")
                logger.info(email)
                logger.info(user)
                logger.info(UserEmail)

                #UserEmail.objects.get_or_create(user=user, email=email)
                #[0]
                logger.info("HIT 2 F")

        logger.info("HIT 2 G")
        member_role = _get_effective_sentry_role(ldap_user.group_names)
        logger.info("HIT 3")
        if not member_role:
            member_role = getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_ROLE_TYPE', None)

        has_global_access = getattr(settings, 'AUTH_LDAP_SENTRY_ORGANIZATION_GLOBAL_ACCESS', False)
        
        orgs = OrganizationMember.objects.filter(user=user)
        logger.info("HIT 4")
        if orgs == None or len(orgs) == 0:  # user is not in any organisation
            if settings.AUTH_LDAP_DEFAULT_SENTRY_ORGANIZATION:  # user should be added to an organisation
                organizations = Organization.objects.filter(slug=settings.AUTH_LDAP_DEFAULT_SENTRY_ORGANIZATION)    

                if not organizations or len(organizations) < 1:
                    logger.error("The default organization from the ldap config does not exist")

                    return model
                OrganizationMember.objects.create(  # Add the user to the organization
                    organization=organizations[0],
                    user=user,
                    role=member_role,
                    has_global_access=has_global_access,
                    flags=getattr(OrganizationMember.flags, u'sso:linked')
                )
        else:   # user is in organisation update it's role
            orgs[0].role = member_role
            orgs[0].save()
          

        if not getattr(settings, 'AUTH_LDAP_SENTRY_SUBSCRIBE_BY_DEFAULT', True):

            UserOption.objects.set_value(
                user=user,
                project=None,
                key='subscribe_by_default',
                value='0',
            )
        return model
