// eslint-disable-next-line no-undef
define(['edx-ui-toolkit/js/utils/spec-helpers/ajax-helpers', 'js/student_account/shoppingcart'],
    function(AjaxHelpers, ShoppingCartInterface) {
        'use strict';

        describe('ShoppingCartInterface', function() {
            // eslint-disable-next-line no-var
            var COURSE_KEY = 'edX/DemoX/Fall',
                ADD_COURSE_URL = '/shoppingcart/add/course/edX/DemoX/Fall/',
                FORWARD_URL = '/shoppingcart/';

            beforeEach(function() {
                // Mock the redirect call
                // eslint-disable-next-line no-undef
                spyOn(ShoppingCartInterface, 'redirect').and.callFake(function() {});
            });

            it('adds a course to the cart', function() {
                // Spy on Ajax requests
                // eslint-disable-next-line no-var
                var requests = AjaxHelpers.requests(this);

                // Attempt to add a course to the cart
                ShoppingCartInterface.addCourseToCart(COURSE_KEY);

                // Expect that the correct request was made to the server
                AjaxHelpers.expectRequest(requests, 'POST', ADD_COURSE_URL);

                // Simulate a successful response from the server
                AjaxHelpers.respondWithJson(requests, {});

                // Expect that the user was redirected to the shopping cart
                expect(ShoppingCartInterface.redirect).toHaveBeenCalledWith(FORWARD_URL);
            });

            it('redirects the user on a server error', function() {
                // Spy on Ajax requests
                // eslint-disable-next-line no-var
                var requests = AjaxHelpers.requests(this);

                // Attempt to add a course to the cart
                ShoppingCartInterface.addCourseToCart(COURSE_KEY);

                // Simulate an error response from the server
                AjaxHelpers.respondWithError(requests);

                // Expect that the user was redirected to the shopping cart
                expect(ShoppingCartInterface.redirect).toHaveBeenCalledWith(FORWARD_URL);
            });
        });
    }
);
