# pylint: disable=missing-docstring

from datetime import datetime, timedelta

import factory
from factory.django import DjangoModelFactory
from factory.fuzzy import FuzzyText
import pytz

from oauth2_provider.models import get_application_model, AccessToken, RefreshToken

from openedx.core.djangoapps.oauth_dispatch.models import ApplicationAccess
from student.tests.factories import UserFactory


Application = get_application_model()


class ApplicationFactory(DjangoModelFactory):
    class Meta(object):
        model = Application

    user = factory.SubFactory(UserFactory)
    client_id = factory.Sequence(u'client_{0}'.format)
    client_secret = 'some_secret'
    client_type = 'confidential'
    authorization_grant_type = 'Client credentials'


class ApplicationAccessFactory(DjangoModelFactory):
    class Meta(object):
        model = ApplicationAccess

    application = factory.SubFactory(ApplicationFactory)
    scopes = ['grades:read']


class AccessTokenFactory(DjangoModelFactory):
    class Meta(object):
        model = AccessToken
        django_get_or_create = ('user', 'application')

    token = FuzzyText(length=32)
    expires = datetime.now(pytz.UTC) + timedelta(days=1)


class RefreshTokenFactory(DjangoModelFactory):
    class Meta(object):
        model = RefreshToken
        django_get_or_create = ('user', 'application')

    token = FuzzyText(length=32)
