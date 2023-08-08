/* eslint-disable-next-line no-shadow-restricted-names, no-unused-vars */
(function(define, undefined) {
    'use strict';

    define([
        'gettext', 'underscore', 'backbone'
    ], function(gettext, _, Backbone) {
        // eslint-disable-next-line no-var
        var UserAccountModel = Backbone.Model.extend({
            idAttribute: 'username',
            defaults: {
                username: '',
                name: '',
                email: '',
                password: '',
                language: null,
                country: null,
                date_joined: '',
                gender: null,
                goals: '',
                level_of_education: null,
                mailing_address: '',
                year_of_birth: null,
                bio: null,
                social_links: [],
                language_proficiencies: [],
                requires_parental_consent: true,
                profile_image: null,
                accomplishments_shared: false,
                default_public_account_fields: [],
                extended_profile: [],
                secondary_email: ''
            },

            parse: function(response) {
                if (_.isNull(response) || _.isUndefined(response)) {
                    return {};
                }

                // Currently when a non-staff user A access user B's profile, the only way to tell whether user B's
                // profile is public is to check if the api has returned fields other than the default public fields
                // specified in settings.ACCOUNT_VISIBILITY_CONFIGURATION.
                // eslint-disable-next-line no-var
                var responseKeys = _.filter(_.keys(response), function(key) {
                    return key !== 'default_public_account_fields';
                });

                // eslint-disable-next-line no-var
                var isPublic = _.size(_.difference(responseKeys, response.default_public_account_fields)) > 0;
                response.profile_is_public = isPublic;
                return response;
            },

            hasProfileImage: function() {
                /* eslint-disable-next-line camelcase, no-var */
                var profile_image = this.get('profile_image');
                // eslint-disable-next-line camelcase
                return (_.isObject(profile_image) && profile_image.has_image === true);
            },

            profileImageUrl: function() {
                return this.get('profile_image').image_url_large;
            },

            isAboveMinimumAge: function() {
                // eslint-disable-next-line no-var
                var yearOfBirth = this.get('year_of_birth'),
                    isBirthDefined = !(_.isUndefined(yearOfBirth) || _.isNull(yearOfBirth)),
                    minimumAllowedAge = this.get('parental_consent_age_limit'),
                    enableCoppaCompliance = this.get('enable_coppa_compliance');

                if (enableCoppaCompliance) {
                    // eslint-disable-next-line no-var
                    var currentYear = new Date().getFullYear(),
                        isOlderThanMinimum = (currentYear - yearOfBirth) >= minimumAllowedAge;
                    return isBirthDefined && isOlderThanMinimum && !(this.get('requires_parental_consent'));
                }
                return isBirthDefined && !(this.get('requires_parental_consent'));
            }
        });
        return UserAccountModel;
    });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
