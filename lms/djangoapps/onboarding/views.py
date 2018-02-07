"""
Views for on-boarding app.
"""
import base64
import json
import logging
from datetime import datetime

import os
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.http import JsonResponse
from django.shortcuts import redirect
from django.shortcuts import render
from django.utils.translation import ugettext_lazy as _, ugettext_noop
from django.views.decorators.csrf import csrf_exempt
from path import Path as path

from edxmako.shortcuts import render_to_response
from lms.djangoapps.onboarding.decorators import can_save_org_data, can_not_update_onboarding_steps, \
    can_save_org_details
from lms.djangoapps.onboarding.email_utils import send_admin_activation_email, send_admin_update_confirmation_email, send_admin_update_email
from lms.djangoapps.onboarding.helpers import calculate_age_years, COUNTRIES
from lms.djangoapps.onboarding.models import (
    Organization,
    Currency, OrganizationMetric, OrganizationAdminHashKeys, PartnerNetwork)
from lms.djangoapps.onboarding.models import UserExtendedProfile
from lms.djangoapps.onboarding.signals import save_interests
from lms.djangoapps.student_dashboard.views import get_recommended_xmodule_courses, get_recommended_communities
from nodebb.helpers import update_nodebb_for_user_status
from onboarding import forms

log = logging.getLogger("edx.onboarding")


@login_required
@can_not_update_onboarding_steps
@transaction.atomic
def user_info(request):
    """
    The view to handle user info survey from the user.

    If its a GET request then an empty form for survey is returned
    otherwise, a form is populated form the POST request data and
    is then saved. After saving the form, user is redirected to the
    next survey namely, interests survey.
    """

    user_extended_profile = request.user.extended_profile
    are_forms_complete = not (bool(user_extended_profile.unattended_surveys(_type='list')))
    userprofile = request.user.profile
    is_under_age = False

    template = 'onboarding/tell_us_more_survey.html'
    next_page_url = reverse('interests')
    redirect_to_next = True

    if request.path == reverse('additional_information'):
        redirect_to_next = False
        template = 'myaccount/additional_information.html'

    initial = {
        'year_of_birth': userprofile.year_of_birth,
        'gender': userprofile.gender,
        'language': userprofile.language,
        'country': COUNTRIES.get(userprofile.country) if not request.POST.get('country') else request.POST.get('country'),
        'country_of_employment': COUNTRIES.get(user_extended_profile.country_of_employment, '') if not request.POST.get('country_of_employment') else request.POST.get('country_of_employment') ,
        'city': userprofile.city,
        'level_of_education': userprofile.level_of_education,
        'hours_per_week': user_extended_profile.hours_per_week if user_extended_profile.hours_per_week else '',
        'is_emp_location_different': True if user_extended_profile.country_of_employment else False,
        "function_areas": user_extended_profile.get_user_selected_functions(_type="fields")
    }

    context = {
        'are_forms_complete': are_forms_complete, 'first_name': request.user.first_name
    }

    year_of_birth = userprofile.year_of_birth

    if request.method == 'POST':
        year_of_birth = request.POST.get('year_of_birth')

    if year_of_birth:
        years = calculate_age_years(int(year_of_birth))
        if years < 13:
            is_under_age = True

    if request.method == 'POST':
        form = forms.UserInfoModelForm(request.POST, instance=user_extended_profile, initial=initial)

        if form.is_valid() and not is_under_age:
            form.save(request)

            are_forms_complete = not (bool(user_extended_profile.unattended_surveys(_type='list')))

            if not are_forms_complete and redirect_to_next:
                return redirect(next_page_url)

    else:
        form = forms.UserInfoModelForm(instance=user_extended_profile, initial=initial)

    context.update({
        'form': form,
        'is_under_age': is_under_age,
        'non_profile_organization': Organization.is_non_profit(user_extended_profile),
        'is_poc': user_extended_profile.is_organization_admin,
        'is_first_user': user_extended_profile.organization.is_first_signup_in_org() \
        if user_extended_profile.organization else False,
        'google_place_api_key': settings.GOOGLE_PLACE_API_KEY,

    })

    context.update(user_extended_profile.unattended_surveys())
    return render(request, template, context)


@login_required
@can_not_update_onboarding_steps
@transaction.atomic
def interests(request):
    """
    The view to handle interests survey from the user.

    If its a GET request then an empty form for survey is returned
    otherwise, a form is populated form the POST request and then is
    saved. After saving the form, user is redirected to the next survey
    namely, organization survey.
    """
    user_extended_profile = request.user.extended_profile
    are_forms_complete = not(bool(user_extended_profile.unattended_surveys(_type='list')))
    is_first_signup_in_org = user_extended_profile.organization.is_first_signup_in_org() \
        if user_extended_profile.organization else False

    template = 'onboarding/interests_survey.html'
    next_page_url = reverse('organization')
    redirect_to_next = True

    if request.path == reverse('update_interests'):
        redirect_to_next = False
        template = 'myaccount/interests.html'

    initial = {
        "interests": user_extended_profile.get_user_selected_interests(_type="fields"),
        "interested_learners": user_extended_profile.get_user_selected_interested_learners(_type="fields"),
        "personal_goals": user_extended_profile.get_user_selected_personal_goal(_type="fields")
    }

    if request.method == 'POST':
        form = forms.InterestsForm(request.POST, initial=initial)

        is_action_update = user_extended_profile.is_interests_data_submitted

        form.save(request, user_extended_profile)

        save_interests.send(sender=UserExtendedProfile, instance=user_extended_profile)

        are_forms_complete = not (bool(user_extended_profile.unattended_surveys(_type='list')))

        if (user_extended_profile.is_organization_admin or is_first_signup_in_org) and not are_forms_complete \
                and redirect_to_next:
            return redirect(next_page_url)

        if are_forms_complete and not is_action_update:
            update_nodebb_for_user_status(request.user.username)
            return redirect(reverse('recommendations'))

    else:
        form = forms.InterestsForm(initial=initial)

    context = {'form': form, 'are_forms_complete': are_forms_complete}

    user = request.user
    extended_profile = user.extended_profile
    context.update(extended_profile.unattended_surveys())

    context.update({
        'non_profile_organization': Organization.is_non_profit(user_extended_profile),
        'is_poc': extended_profile.is_organization_admin,
        'is_first_user': is_first_signup_in_org,
    })

    return render(request, template, context)


@login_required
@can_save_org_data
@can_not_update_onboarding_steps
@transaction.atomic
def organization(request):
    """
    The view to handle organization survey from the user.

    If its a GET request then an empty form for survey is returned
    otherwise, a form is populated form the POST request and then is
    saved. After saving the form, user is redirected to recommendations page.
    """
    user_extended_profile = request.user.extended_profile
    _organization = user_extended_profile.organization
    are_forms_complete = not(bool(user_extended_profile.unattended_surveys(_type='list')))

    template = 'onboarding/organization_survey.html'
    next_page_url = reverse('recommendations')
    redirect_to_next = True

    if request.path == reverse('update_organization'):
        redirect_to_next = False
        template = 'organization/update_organization.html'

    initial = {
        'country': COUNTRIES.get(_organization.country),
        'is_org_url_exist': '1' if _organization.url else '0',
        'partner_networks': _organization.organization_partners.values_list('partner', flat=True),
    }

    if request.method == 'POST':
        old_url = request.POST.get('url', '').replace('http://', 'https://', 1)
        form = forms.OrganizationInfoForm(request.POST, instance=_organization, initial=initial)

        if form.is_valid():
            form.save(request)
            old_url = _organization.url.replace('https://', '', 1) if _organization.url else _organization.url
            are_forms_complete = not (bool(user_extended_profile.unattended_surveys(_type='list')))

            if user_extended_profile.organization.org_type == PartnerNetwork.NON_PROFIT_ORG_TYPE_CODE:
                # redirect to organization detail page
                next_page_url = reverse('org_detail_survey')
            else:
                #update nodebb for user profile completion
                update_nodebb_for_user_status(request.user.username)

            if redirect_to_next:
                return redirect(next_page_url)

    else:
        old_url = _organization.url.replace('https://', '', 1) if _organization.url else _organization.url
        form = forms.OrganizationInfoForm(instance=_organization, initial=initial)

    context = {'form': form, 'are_forms_complete': are_forms_complete, 'old_url': old_url}

    organization = user_extended_profile.organization
    context.update(user_extended_profile.unattended_surveys())

    context.update({
        'non_profile_organization': Organization.is_non_profit(user_extended_profile),
        'is_poc': user_extended_profile.is_organization_admin,
        'is_first_user': organization.is_first_signup_in_org() if user_extended_profile.organization else False,
        'org_admin_id': organization.admin_id if user_extended_profile.organization else None,
        'organization_name': _organization.label,
        'google_place_api_key': settings.GOOGLE_PLACE_API_KEY
    })

    return render(request, template, context)


@login_required
def delete_my_account(request):
    user = request.user

    try:
        logout(request)
        user = User.objects.get(id=user.id)
        user.delete()
        data = json.dumps({"status": 200})
    except User.DoesNotExist:
        log.info("User does not exists")
        data = json.dumps({"status": 200})

    mime_type = 'application/json'
    return HttpResponse(data, mime_type)


@csrf_exempt
def get_country_names(request):
    """
    Returns country names.
    """
    if request.is_ajax():
        q = request.GET.get('term', '')
        all_countries = COUNTRIES.values()

        filtered_countries = [country for country in all_countries if country.lower().startswith(q.lower())]

        data = json.dumps(filtered_countries)

    else:
        data = 'fail'

    mime_type = 'application/json'

    return HttpResponse(data, mime_type)


@login_required
@can_save_org_details
@can_not_update_onboarding_steps
@transaction.atomic
def org_detail_survey(request):
    user_extended_profile = request.user.extended_profile
    are_forms_complete = not(bool(user_extended_profile.unattended_surveys(_type='list')))

    latest_survey = OrganizationMetric.objects.filter(org=user_extended_profile.organization,
                                                      user=request.user).last()

    initial = {
        'actual_data': '1' if latest_survey and latest_survey.actual_data else '0',
        "effective_date": datetime.strftime(latest_survey.effective_date, '%d/%m/%Y') if latest_survey else ""
    }

    template = 'onboarding/organization_detail_survey.html'
    next_page_url = reverse('oef_survey')
    org_metric_form = forms.OrganizationMetricModelForm
    redirect_to_next = True

    if request.path == reverse('update_organization_details'):
        redirect_to_next = False
        template = 'organization/update_organization_details.html'
        org_metric_form = forms.OrganizationMetricModelUpdateForm

    if request.method == 'POST':
        if latest_survey:
            form = org_metric_form(request.POST, instance=latest_survey, initial=initial)
        else:
            form = org_metric_form(request.POST, initial=initial)

        if form.is_valid():
            form.save(request)

            are_forms_complete = not (bool(user_extended_profile.unattended_surveys(_type='list')))

            if are_forms_complete and redirect_to_next:
                update_nodebb_for_user_status(request.user.username)
                return redirect(next_page_url)

    else:
        if latest_survey:
            form = org_metric_form(instance=latest_survey, initial=initial)
        else:
            form = org_metric_form()

    context = {'form': form, 'are_forms_complete': are_forms_complete}
    context.update(user_extended_profile.unattended_surveys())

    context.update({
        'non_profile_organization': Organization.is_non_profit(user_extended_profile),
        'is_poc': user_extended_profile.is_organization_admin,
        'is_first_user': user_extended_profile.organization.is_first_signup_in_org()\
            if user_extended_profile.organization else False,
        'organization_name': user_extended_profile.organization.label,
    })

    return render(request, template, context)


@csrf_exempt
def get_languages(request):
    """
    Returns languages
    """
    if request.is_ajax():
        file_path = path(os.path.join(
            'lms', 'djangoapps', 'onboarding', 'data', 'world_languages.json'
        )).abspath()
        with open(file_path) as json_data:
            q = request.GET.get('term', '')
            all_languages = json.load(json_data)
            filtered_languages = [language for language in all_languages if language.lower().startswith(q.lower())]

        data = json.dumps(filtered_languages)

    else:
        data = 'fail'

    mime_type = 'application/json'

    return HttpResponse(data, mime_type)


@login_required
def update_account_settings(request):
    """
    View to handle update of registration extra fields
    """

    user_extended_profile = UserExtendedProfile.objects.get(user_id=request.user.id)
    if request.method == 'POST':

        form = forms.UpdateRegModelForm(request.POST, instance=user_extended_profile)
        if form.is_valid():
            user_extended_profile = form.save(user=user_extended_profile.user, commit=True)
            are_forms_complete = not (bool(user_extended_profile.unattended_surveys(_type='list')))

            if not are_forms_complete :
                return redirect(reverse('organization'))

    else:
        form = forms.UpdateRegModelForm(
            instance=user_extended_profile,
            initial={
                'organization_name': user_extended_profile.organization.label if user_extended_profile.organization else "",
                'is_poc': "1" if user_extended_profile.is_organization_admin else "0",
                'first_name': user_extended_profile.user.first_name,
                'last_name': user_extended_profile.user.last_name
            }
        )

    return render(
        request, 'myaccount/registration_update.html',
        {'form': form, 'org_url': reverse('get_organizations')}
    )


@login_required
def suggest_org_admin(request):
    """
    Suggest a user as administrator of an organization
    """
    status = 200
    message = 'Email successfully sent'

    if request.method == 'POST':
        organization = request.POST.get('organization')
        org_admin_email = request.POST.get('email')

        if organization:
            try:
                organization = Organization.objects.get(label__iexact=organization)
                extended_profile = request.user.extended_profile

                if org_admin_email:
                    already_an_admin = Organization.objects.filter(admin__email=org_admin_email).first()
                    if already_an_admin:
                        status = 400
                        message = ugettext_noop('%s is already admin of organization "%s"'
                                                      % (org_admin_email, already_an_admin.label))
                    else:
                        hash_key = OrganizationAdminHashKeys.assign_hash(organization, request.user, org_admin_email)
                        org_id = extended_profile.organization_id
                        org_name = extended_profile.organization.label
                        organization.unclaimed_org_admin_email = org_admin_email

                        send_admin_activation_email(request.user.first_name, org_id, org_name, org_admin_email,
                                                    hash_key)
                else:
                    hash_key = OrganizationAdminHashKeys.assign_hash(organization, request.user, request.user.email)
                    send_admin_update_email(organization.id, organization.label, organization.admin.email,
                                            hash_key, request.user.email, request.user.username
                                            )

            except Organization.DoesNotExist:
                log.info("Organization does not exists: %s" % organization)
                status = 400
            except Exception as ex:
                log.info(ex.args)
                status = 400

    return JsonResponse({'status': status, 'message': message})


@csrf_exempt
def get_organizations(request):
    """
    Get organizations
    """
    final_result = {}
    org_label = ''
    admin_email = ''

    if request.is_ajax():
        query = request.GET.get('term', '')
        all_organizations = Organization.objects.filter(label__istartswith=query)

        for organization in all_organizations:
            final_result[organization.label] = {
                'is_admin_assigned': True if organization.admin else False,
                'is_current_user_admin': True if organization.admin == request.user else False,
                'admin_email': organization.admin.email if organization.admin else ''
            }

        if request.user.is_authenticated():
            user_extended_profile = request.user.extended_profile
            organization = user_extended_profile.organization

            if organization:
                _result = {
                    'org': organization.label,
                    'is_poc': True if organization.admin == request.user else False,
                    'admin_email': organization.admin.email if organization.admin else ''
                }
            else:
                _result = {
                    'org': '',
                    'is_poc': False,
                    'admin_email': ''
                }

            final_result['user_org_info'] = _result

    return JsonResponse(final_result)


@csrf_exempt
def get_currencies(request):
    currencies = []

    if request.is_ajax():
        term = request.GET.get('term', '')
        currencies = Currency.objects.filter(alphabetic_code__istartswith=term).values_list('alphabetic_code',
                                                                                            flat=True).distinct()
    data = json.dumps(list(currencies))
    return HttpResponse(data, 'application/json')


@login_required
def recommendations(request):
    """
    Display recommended courses and communities based on the survey

    """
    recommended_courses = get_recommended_xmodule_courses(request.user)
    recommended_communities = get_recommended_communities(request.user)
    context = {
        'recommended_courses': recommended_courses,
        'recommended_communities': recommended_communities,
    }

    return render_to_response('onboarding/recommendations.html', context)


@csrf_exempt
@transaction.atomic
def admin_activation(request, activation_key):
    """
        When clicked on link sent in email to make user admin.

        activation_status can have values 1, 2, 3, 4, 5.
        1 = Activated
        2 = Already Active
        3 = Invalid Hash
        4 = To be Activated
        5 = User not exist in platform

    """
    context = {}
    admin_activation = True if request.GET.get('admin_activation') == 'True' else False

    try:
        hash_key = OrganizationAdminHashKeys.objects.get(activation_hash=activation_key)
        admin_change_confirmation = True if request.GET.get('confirm') == 'True' else False
        user_extended_profile = UserExtendedProfile.objects.get(user__email=hash_key.suggested_admin_email)
        user = user_extended_profile.user

        context['key'] = hash_key.activation_hash
        if hash_key.is_hash_consumed:
            activation_status = 2
        else:
            activation_status = 4

        # Proceed only if hash_key is not already consumed
        if request.method == 'POST' and activation_status != 2:
            hash_key.is_hash_consumed = True
            hash_key.save()
            # Consume all entries of hash keys where suggested_admin_email = hash_key.suggested_admin_email,
            # so he can not use those links in future
            unconsumed_hash_keys = OrganizationAdminHashKeys.objects.filter(
                is_hash_consumed=False, suggested_admin_email=hash_key.suggested_admin_email
            )
            if unconsumed_hash_keys:
                unconsumed_hash_keys.update(is_hash_consumed=True)

            # Change the admin of the organization if admin is being activated or updated on user confirmation[True]
            if admin_activation or admin_change_confirmation:

                # If claimer's is admin of some other organization remove his privileges
                # for that organization as he can only be an admin of single organization
                if user_extended_profile.organization and user_extended_profile.organization.admin == user:
                    user_extended_profile.organization.admin = None
                    user_extended_profile.organization.save()

                hash_key.organization.unclaimed_org_admin_email = None
                hash_key.organization.admin = user
                hash_key.organization.save()

                # Update the claimer's organization if a user confirms
                user_extended_profile.organization = hash_key.organization
                user_extended_profile.save()
                activation_status = 1

            if not admin_activation:
                # Send an email to claimer, on admin updation depending upon whether user accepts or rejects the request
                send_admin_update_confirmation_email(hash_key.organization.label, user.email,
                                                     confirm=1 if admin_change_confirmation else None)
                return HttpResponseRedirect('/myaccount/settings/')

    except OrganizationAdminHashKeys.DoesNotExist:
        activation_status = 3

    except UserExtendedProfile.DoesNotExist:
        activation_status = 5

    if activation_status == 5 and admin_activation:
        hash_key.is_hash_consumed = True
        hash_key.save()

        url = reverse('register_user', kwargs={
            'initial_mode': 'register',
            'org_name': base64.b64encode(str(hash_key.organization.label)),
            'admin_email': base64.b64encode(str(hash_key.suggested_admin_email))})

        messages.add_message(request, messages.INFO,
                             _('Please signup here to become admin for %s' % hash_key.organization.label))
        return HttpResponseRedirect(url)

    context['activation_status'] = activation_status

    if admin_activation:
        return render_to_response('onboarding/admin_activation.html', context)

    context['username'] = user.username if user else None
    return render_to_response('onboarding/admin_change_confirmation.html', context)


