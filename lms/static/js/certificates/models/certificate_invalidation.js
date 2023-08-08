// Backbone.js Application Model: CertificateInvalidation
// eslint-disable-next-line no-redeclare
/* global define, RequireJS */

(function(define) {
    'use strict';

    define(
        ['underscore', 'underscore.string', 'gettext', 'backbone'],

        function(_, str, gettext, Backbone) {
            return Backbone.Model.extend({
                idAttribute: 'id',

                defaults: {
                    user: '',
                    invalidated_by: '',
                    created: '',
                    notes: ''
                },

                initialize: function(attributes, options) {
                    this.url = options.url;
                },

                // eslint-disable-next-line consistent-return
                validate: function(attrs) {
                    if (!str.trim(attrs.user)) {
                        // A username or email must be provided for certificate invalidation
                        return gettext('Student username/email field is required and can not be empty. '
                            + 'Kindly fill in username/email and then press "Invalidate Certificate" button.');
                    }
                }
            });
        }
    );
}).call(this, define || RequireJS.define);
