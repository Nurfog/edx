"""
Certificates Data Model:

course.certificates: {
    'certificates': [
        {
            'version': 1, // data contract version
            'id': 12345, // autogenerated identifier
            'name': 'Certificate 1',
            'description': 'Certificate 1 Description',
            'course_title': 'course title',
            'signatories': [
                {
                    'id': 24680, // autogenerated identifier
                    'name': 'Dr. Bob Smith',
                    'title': 'Dean of the College',
                    'organization': 'Awesome College'
                }
            ]
        }
    ]
}
"""


import json
import logging

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.utils.translation import gettext as _
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from eventtracking import tracker
from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import AssetKey, CourseKey

from common.djangoapps.course_modes.models import CourseMode
from common.djangoapps.edxmako.shortcuts import render_to_response
from common.djangoapps.student.auth import has_studio_write_access
from common.djangoapps.student.roles import GlobalStaff
from common.djangoapps.util.db import MYSQL_MAX_INT, generate_int_id
from common.djangoapps.util.json_request import JsonResponse
from xmodule.modulestore import EdxJSONEncoder  # lint-amnesty, pylint: disable=wrong-import-order
from xmodule.modulestore.django import modulestore  # lint-amnesty, pylint: disable=wrong-import-order

from ..exceptions import AssetNotFoundException
from ..utils import (
    get_lms_link_for_certificate_web_view,
    get_proctored_exam_settings_url,
    reverse_course_url
)
from .assets import delete_asset

CERTIFICATE_SCHEMA_VERSION = 1
CERTIFICATE_MINIMUM_ID = 100

LOGGER = logging.getLogger(__name__)


def _get_course_and_check_access(course_key, user, depth=0):
    """
    Internal method used to calculate and return the locator and
    course module for the view functions in this file.
    """
    if not has_studio_write_access(user, course_key):
        raise PermissionDenied()
    course_module = modulestore().get_course(course_key, depth=depth)
    return course_module


def _delete_asset(course_key, asset_key_string):
    """
    Internal method used to create asset key from string and
    remove asset by calling delete_asset method of assets module.
    """
    if asset_key_string:
        try:
            asset_key = AssetKey.from_string(asset_key_string)
        except InvalidKeyError:
            # remove first slash in asset path
            # otherwise it generates InvalidKeyError in case of split modulestore
            if '/' == asset_key_string[0]:
                asset_key_string = asset_key_string[1:]
                try:
                    asset_key = AssetKey.from_string(asset_key_string)
                except InvalidKeyError:
                    # Unable to parse the asset key, log and return
                    LOGGER.info(
                        "In course %r, unable to parse asset key %r, not attempting to delete signatory.",
                        course_key,
                        asset_key_string,
                    )
                    return
            else:
                # Unable to parse the asset key, log and return
                LOGGER.info(
                    "In course %r, unable to parse asset key %r, not attempting to delete signatory.",
                    course_key,
                    asset_key_string,
                )
                return

        try:
            delete_asset(course_key, asset_key)
        # If the asset was not found, it doesn't have to be deleted...
        except AssetNotFoundException:
            pass


# Certificates Exceptions
class CertificateException(Exception):
    """
    Base exception for Certificates workflows
    """
    pass  # lint-amnesty, pylint: disable=unnecessary-pass


class CertificateValidationError(CertificateException):
    """
    An exception raised when certificate information is invalid.
    """
    pass  # lint-amnesty, pylint: disable=unnecessary-pass


class CertificateManager:
    """
    The CertificateManager is responsible for storage, retrieval, and manipulation of Certificates
    Certificates are not stored in the Django ORM, they are a field/setting on the course descriptor
    """
    @staticmethod
    def parse(json_string):
        """
        Deserialize the provided JSON data into a standard Python object
        """
        try:
            certificate = json.loads(json_string)
        except ValueError:
            raise CertificateValidationError(_("invalid JSON"))  # lint-amnesty, pylint: disable=raise-missing-from
        # Include the data contract version
        certificate["version"] = CERTIFICATE_SCHEMA_VERSION
        # Ensure a signatories list is always returned
        if certificate.get("signatories") is None:
            certificate["signatories"] = []
        certificate["editing"] = False
        return certificate

    @staticmethod
    def validate(certificate_data):
        """
        Ensure the certificate data contains all of the necessary fields and the values match our rules
        """
        # Ensure the schema version meets our expectations
        if certificate_data.get("version") != CERTIFICATE_SCHEMA_VERSION:
            raise TypeError(
                "Unsupported certificate schema version: {}.  Expected version: {}.".format(
                    certificate_data.get("version"),
                    CERTIFICATE_SCHEMA_VERSION
                )
            )
        if not certificate_data.get("name"):
            raise CertificateValidationError(_("must have name of the certificate"))

    @staticmethod
    def is_activated(course):
        """
        Returns whether certificates are activated for the given course,
        along with the certificates.
        """
        is_active = False
        certificates = None
        if settings.FEATURES.get('CERTIFICATES_HTML_VIEW', False):
            certificates = CertificateManager.get_certificates(course)
            # we are assuming only one certificate in certificates collection.
            for certificate in certificates:
                is_active = certificate.get('is_active', False)
                break
        return is_active, certificates

    @staticmethod
    def get_used_ids(course):
        """
        Return a list of certificate identifiers that are already in use for this course
        """
        if not course.certificates or not course.certificates.get('certificates'):
            return []
        return [cert['id'] for cert in course.certificates['certificates']]

    @staticmethod
    def assign_id(course, certificate_data, certificate_id=None):
        """
        Assign an identifier to the provided certificate data.
        If the caller did not provide an identifier, we autogenerate a unique one for them
        In addition, we check the certificate's signatories and ensure they also have unique ids
        """
        used_ids = CertificateManager.get_used_ids(course)
        if certificate_id:
            certificate_data['id'] = int(certificate_id)
        else:
            certificate_data['id'] = generate_int_id(
                CERTIFICATE_MINIMUM_ID,
                MYSQL_MAX_INT,
                used_ids
            )

        for index, signatory in enumerate(certificate_data['signatories']):  # pylint: disable=unused-variable
            if signatory and not signatory.get('id', False):
                signatory['id'] = generate_int_id(used_ids=used_ids)
            used_ids.append(signatory['id'])

        return certificate_data

    @staticmethod
    def serialize_certificate(certificate):
        """
        Serialize the Certificate object's locally-stored certificate data to a JSON representation
        We use direct access here for specific keys in order to enforce their presence
        """
        certificate_data = certificate.certificate_data
        certificate_response = {
            "id": certificate_data['id'],
            "name": certificate_data['name'],
            "description": certificate_data['description'],
            "is_active": certificate_data['is_active'],
            "version": CERTIFICATE_SCHEMA_VERSION,
            "signatories": certificate_data['signatories']
        }

        # Some keys are not required, such as the title override...
        if certificate_data.get('course_title'):
            certificate_response["course_title"] = certificate_data['course_title']
        if certificate_data.get('course_description'):
            certificate_response['course_description'] = certificate_data['course_description']

        return certificate_response

    @staticmethod
    def deserialize_certificate(course, value):
        """
        Deserialize from a JSON representation into a Certificate object.
        'value' should be either a Certificate instance, or a valid JSON string
        """
        if isinstance(value, bytes):
            value = value.decode('utf-8')

        # Ensure the schema fieldset meets our expectations
        for key in ("name", "description", "version"):
            if key not in value:
                raise CertificateValidationError(_("Certificate dict {0} missing value key '{1}'").format(value, key))

        # Load up the Certificate data
        certificate_data = CertificateManager.parse(value)
        CertificateManager.validate(certificate_data)
        certificate_data = CertificateManager.assign_id(course, certificate_data, certificate_data.get('id', None))
        certificate = Certificate(course, certificate_data)

        # Return a new Certificate object instance
        return certificate

    @staticmethod
    def get_certificates(course, only_active=False):
        """
        Retrieve the certificates list from the provided course,
        if `only_active` is True it would skip inactive certificates.
        """
        # The top-level course field is 'certificates', which contains various properties,
        # including the actual 'certificates' list that we're working with in this context
        certificates = course.certificates.get('certificates', [])
        if only_active:
            certificates = [certificate for certificate in certificates if certificate.get('is_active', False)]
        return certificates

    @staticmethod
    def remove_certificate(request, store, course, certificate_id):
        """
        Remove certificate from the course
        """
        for index, cert in enumerate(course.certificates['certificates']):
            if int(cert['id']) == int(certificate_id):
                certificate = course.certificates['certificates'][index]
                # Remove any signatory assets prior to dropping the entire cert record from the course
                for sig_index, signatory in enumerate(certificate.get('signatories')):  # pylint: disable=unused-variable
                    _delete_asset(course.id, signatory['signature_image_path'])
                # Now drop the certificate record
                course.certificates['certificates'].pop(index)
                store.update_item(course, request.user.id)
                break

    # pylint-disable: unused-variable
    @staticmethod
    def remove_signatory(request, store, course, certificate_id, signatory_id):
        """
        Remove the specified signatory from the provided course certificate
        """
        for cert_index, cert in enumerate(course.certificates['certificates']):  # pylint: disable=unused-variable
            if int(cert['id']) == int(certificate_id):
                for sig_index, signatory in enumerate(cert.get('signatories')):
                    if int(signatory_id) == int(signatory['id']):
                        _delete_asset(course.id, signatory['signature_image_path'])
                        del cert['signatories'][sig_index]
                        store.update_item(course, request.user.id)
                        break

    @staticmethod
    def track_event(event_name, event_data):
        """Track certificate configuration event.

        Arguments:
            event_name (str):  Name of the event to be logged.
            event_data (dict): A Dictionary containing event data
        Returns:
            None

        """
        event_name = '.'.join(['edx', 'certificate', 'configuration', event_name])
        tracker.emit(event_name, event_data)


class Certificate:
    """
    The logical representation of an individual course certificate
    """
    def __init__(self, course, certificate_data):
        """
        Instantiate a Certificate object instance using the provided information.
        """
        self.course = course
        self._certificate_data = certificate_data
        self.id = certificate_data['id']  # pylint: disable=invalid-name

    @property
    def certificate_data(self):
        """
        Retrieve the locally-stored certificate data from the Certificate object via a helper method
        """
        return self._certificate_data


@login_required
@require_http_methods(("POST",))
@ensure_csrf_cookie
def certificate_activation_handler(request, course_key_string):
    """
    A handler for Certificate Activation/Deactivation

    POST
        json: is_active. update the activation state of certificate
    """
    course_key = CourseKey.from_string(course_key_string)
    store = modulestore()
    try:
        course = _get_course_and_check_access(course_key, request.user)
    except PermissionDenied:
        msg = _('PermissionDenied: Failed in authenticating {user}').format(user=request.user)
        return JsonResponse({"error": msg}, status=403)

    data = json.loads(request.body.decode('utf8'))
    is_active = data.get('is_active', False)
    certificates = CertificateManager.get_certificates(course)

    # for certificate activation/deactivation, we are assuming one certificate in certificates collection.
    for certificate in certificates:
        certificate['is_active'] = is_active
        break

    store.update_item(course, request.user.id)
    cert_event_type = 'activated' if is_active else 'deactivated'
    CertificateManager.track_event(cert_event_type, {
        'course_id': str(course.id),
    })
    return HttpResponse(status=200)


@login_required
@require_http_methods(("GET", "POST"))
@ensure_csrf_cookie
def certificates_list_handler(request, course_key_string):
    """
    A RESTful handler for Course Certificates

    GET
        html: return Certificates list page (Backbone application)
    POST
        json: create new Certificate
    """
    course_key = CourseKey.from_string(course_key_string)
    store = modulestore()
    with store.bulk_operations(course_key):
        try:
            course = _get_course_and_check_access(course_key, request.user)
        except PermissionDenied:
            msg = _('PermissionDenied: Failed in authenticating {user}').format(user=request.user)
            return JsonResponse({"error": msg}, status=403)

        if 'text/html' in request.META.get('HTTP_ACCEPT', 'text/html'):
            certificate_url = reverse_course_url('certificates_list_handler', course_key)
            course_outline_url = reverse_course_url('course_handler', course_key)
            upload_asset_url = reverse_course_url('assets_handler', course_key)
            activation_handler_url = reverse_course_url(
                handler_name='certificate_activation_handler',
                course_key=course_key
            )
            course_modes = [
                mode.slug for mode in CourseMode.modes_for_course(
                    course_id=course.id, include_expired=True
                ) if mode.slug != 'audit'
            ]

            has_certificate_modes = len(course_modes) > 0

            if has_certificate_modes:
                certificate_web_view_url = get_lms_link_for_certificate_web_view(
                    course_key=course_key,
                    mode=course_modes[0]  # CourseMode.modes_for_course returns default mode if doesn't find anyone.
                )
            else:
                certificate_web_view_url = None
            is_active, certificates = CertificateManager.is_activated(course)
            return render_to_response('certificates.html', {
                'context_course': course,
                'certificate_url': certificate_url,
                'course_outline_url': course_outline_url,
                'upload_asset_url': upload_asset_url,
                'certificates': certificates,
                'has_certificate_modes': has_certificate_modes,
                'course_modes': course_modes,
                'certificate_web_view_url': certificate_web_view_url,
                'is_active': is_active,
                'is_global_staff': GlobalStaff().has_user(request.user),
                'certificate_activation_handler_url': activation_handler_url,
                'mfe_proctored_exam_settings_url': get_proctored_exam_settings_url(course.id),
            })
        elif "application/json" in request.META.get('HTTP_ACCEPT'):
            # Retrieve the list of certificates for the specified course
            if request.method == 'GET':
                certificates = CertificateManager.get_certificates(course)
                return JsonResponse(certificates, encoder=EdxJSONEncoder)
            elif request.method == 'POST':
                # Add a new certificate to the specified course
                try:
                    new_certificate = CertificateManager.deserialize_certificate(course, request.body)
                except CertificateValidationError as err:
                    return JsonResponse({"error": str(err)}, status=400)
                if course.certificates.get('certificates') is None:
                    course.certificates['certificates'] = []
                course.certificates['certificates'].append(new_certificate.certificate_data)
                response = JsonResponse(CertificateManager.serialize_certificate(new_certificate), status=201)
                response["Location"] = reverse_course_url(
                    'certificates_detail_handler',
                    course.id,
                    kwargs={'certificate_id': new_certificate.id}
                )
                store.update_item(course, request.user.id)
                CertificateManager.track_event('created', {
                    'course_id': str(course.id),
                    'configuration_id': new_certificate.id
                })
                course = _get_course_and_check_access(course_key, request.user)
                return response
        else:
            return HttpResponse(status=406)


@login_required
@ensure_csrf_cookie
@require_http_methods(("POST", "PUT", "DELETE"))
def certificates_detail_handler(request, course_key_string, certificate_id):
    """
    JSON API endpoint for manipulating a course certificate via its internal identifier.
    Utilized by the Backbone.js 'certificates' application model

    POST or PUT
        json: update the specified certificate based on provided information
    DELETE
        json: remove the specified certificate from the course
    """
    course_key = CourseKey.from_string(course_key_string)
    course = _get_course_and_check_access(course_key, request.user)

    certificates_list = course.certificates.get('certificates', [])
    match_index = None
    match_cert = None
    for index, cert in enumerate(certificates_list):
        if certificate_id is not None:
            if int(cert['id']) == int(certificate_id):
                match_index = index
                match_cert = cert

    store = modulestore()
    if request.method in ('POST', 'PUT'):
        if certificate_id:
            active_certificates = CertificateManager.get_certificates(course, only_active=True)
            if int(certificate_id) in [int(certificate["id"]) for certificate in active_certificates]:
                # Only global staff (PMs) are able to edit active certificate configuration
                if not GlobalStaff().has_user(request.user):
                    raise PermissionDenied()
        try:
            new_certificate = CertificateManager.deserialize_certificate(course, request.body)
        except CertificateValidationError as err:
            return JsonResponse({"error": str(err)}, status=400)

        serialized_certificate = CertificateManager.serialize_certificate(new_certificate)
        cert_event_type = 'created'
        if match_cert:
            cert_event_type = 'modified'
            certificates_list[match_index] = serialized_certificate
        else:
            certificates_list.append(serialized_certificate)

        store.update_item(course, request.user.id)
        CertificateManager.track_event(cert_event_type, {
            'course_id': str(course.id),
            'configuration_id': serialized_certificate["id"]
        })
        return JsonResponse(serialized_certificate, status=201)

    elif request.method == "DELETE":
        if not match_cert:
            return JsonResponse(status=404)

        active_certificates = CertificateManager.get_certificates(course, only_active=True)
        if int(certificate_id) in [int(certificate["id"]) for certificate in active_certificates]:
            # Only global staff (PMs) are able to delete active certificate configuration
            if not GlobalStaff().has_user(request.user):
                raise PermissionDenied()

        CertificateManager.remove_certificate(
            request=request,
            store=store,
            course=course,
            certificate_id=certificate_id
        )
        CertificateManager.track_event('deleted', {
            'course_id': str(course.id),
            'configuration_id': certificate_id
        })
        return JsonResponse(status=204)


@login_required
@ensure_csrf_cookie
@require_http_methods(("POST", "PUT", "DELETE"))
def signatory_detail_handler(request, course_key_string, certificate_id, signatory_id):
    """
    JSON API endpoint for manipulating a specific course certificate signatory via its internal identifier.
    Utilized by the Backbone 'certificates' application.

    DELETE
        json: Remove the specified signatory from the specified certificate
    """
    course_key = CourseKey.from_string(course_key_string)
    store = modulestore()
    with store.bulk_operations(course_key):
        course = _get_course_and_check_access(course_key, request.user)
        certificates_list = course.certificates['certificates']

        match_cert = None
        # pylint: disable=unused-variable
        for index, cert in enumerate(certificates_list):
            if certificate_id is not None:
                if int(cert['id']) == int(certificate_id):
                    match_cert = cert

        if request.method == "DELETE":
            if not match_cert:
                return JsonResponse(status=404)
            CertificateManager.remove_signatory(
                request=request,
                store=store,
                course=course,
                certificate_id=certificate_id,
                signatory_id=signatory_id
            )
            return JsonResponse(status=204)
