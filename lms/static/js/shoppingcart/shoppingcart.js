/* eslint-disable-next-line no-use-before-define, no-var */
var edx = edx || {};

(function($) {
    'use strict';

    edx.shoppingcart = edx.shoppingcart || {};
    edx.shoppingcart.showcart = {};

    /**
     * View for making shoppingcart
     * @constructor
     * @param {Object} params
     * @param {Object} params.el - The payment form element.
     */
    edx.shoppingcart.showcart.CartView = function(params) {
        /**
         * cart view that checks that all the cart items are valid (course enrollment is closed or not)
         * before the form submitted to the payment processor.
         * @param {Object} form - The form to modify.
         */

        /**
        * Check for all the cart items are still valid (courses enrollment are not closed)
        *
        * @returns {Object} The promise from the AJAX call to the server,
        *     which checks for cart items are valid or not and returns the boolean
        *     { is_course_enrollment_closed: <boolead> }
        */
        // eslint-disable-next-line no-var
        var isCourseEnrollmentAllowed = function() {
            return $.ajax({
                url: '/shoppingcart/verify_cart/',
                type: 'GET'
            });
        };

        // eslint-disable-next-line no-var
        var view = {
            /**
            * Initialize the view.
            *
            * @param {Object} params
            * @param {JQuery selector} params.el - The payment form element.
            * @returns {CartView}
            */
            // eslint-disable-next-line no-shadow
            initialize: function(params) {
                this.$el = params.el;
                // eslint-disable-next-line no-undef
                _.bindAll(view,
                    'submit', 'responseFromServer',
                    'submitPaymentForm', 'errorFromServer'
                );
                return this;
            },

            /**
            * Handle a click event on the "payment form submit" button.
            * This will contact the LMS server to check for all the
            * valid cart items (courses enrollment should not be closed at this point)
            * then send the user to the external payment processor or redirects to the
            * dashboard page
            *
            * @param {Object} event - The click event.
            */
            submit: function(event) {
                // Prevent form submission
                if (event) {
                    event.preventDefault();
                }

                // Immediately disable the submit button to prevent duplicate submissions
                this.$el.find('input[type="submit"]').addClass('disabled');

                this.$paymentForm = this.$el;
                isCourseEnrollmentAllowed()
                    .done(this.responseFromServer)
                    .fail(this.errorFromServer);
                return this;
            },

            /**
            * Send signed payment parameters to the external
            * payment processor if cart items are valid else redirect to
            * shoppingcart.
            *
            * @param {boolean} data.is_course_enrollment_closed
            */
            responseFromServer: function(data) {
                // eslint-disable-next-line eqeqeq
                if (data.is_course_enrollment_closed == true) {
                    // eslint-disable-next-line no-restricted-globals
                    location.href = '/shoppingcart';
                } else {
                    this.submitPaymentForm(this.$paymentForm);
                }
            },

            /**
            * In case the server responded back with errors
            *
            */
            errorFromServer: function() {
                // Immediately enable the submit button to allow submission
                this.$el.find('input[type="submit"]').removeClass('disabled');
            },

            /**
            * Submit the payment from to the external payment processor.
            *
            * @param {Object} form
            */
            submitPaymentForm: function(form) {
                form.submit();
            }
        };

        view.initialize(params);
        return view;
    };

    $(document).ready(function() {
        // (click on the payment submit button).
        // eslint-disable-next-line consistent-return
        $('.cart-view form input[type="submit"]').click(function(event) {
            // check if there is code exists in the inout_code field
            // before going to make payment
            // if exists then trigger click event of the apply code button
            // eslint-disable-next-line no-var
            var code = $('div.code-input input#input_code').val();
            // eslint-disable-next-line eqeqeq
            if (typeof code !== 'undefined' && code != '') {
                $('div.code-input #submit-code').trigger('click');
                return false;
            }
            // eslint-disable-next-line no-var
            var $container = $('.confirm-enrollment.cart-view form');
            /* eslint-disable-next-line no-unused-vars, no-var */
            var view = new edx.shoppingcart.showcart.CartView({
                el: $container
            }).submit(event);
        });
    });
// eslint-disable-next-line no-undef
}(jQuery));
