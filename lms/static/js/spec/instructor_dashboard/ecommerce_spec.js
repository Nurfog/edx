// eslint-disable-next-line no-undef
define(['backbone', 'jquery', 'js/instructor_dashboard/ecommerce'],
    function(Backbone, $, ExpiryCouponView) {
        'use strict';

        // eslint-disable-next-line no-var
        var expiryCouponView;
        describe('edx.instructor_dashboard.ecommerce.ExpiryCouponView', function() {
            beforeEach(function() {
                setFixtures('<li class="field full-width" id="add-coupon-modal-field-expiry"><input id="expiry-check" type="checkbox"/><label for="expiry-check"></label><input type="text" id="coupon_expiration_date" class="field" name="expiration_date" aria-required="true"/></li>');
                expiryCouponView = new ExpiryCouponView();
            });

            it('is defined', function() {
                expect(expiryCouponView).toBeDefined();
            });

            it('triggers the callback when the checkbox is clicked', function() {
                // eslint-disable-next-line no-var
                var target = expiryCouponView.$el.find('input[type="checkbox"]');
                // eslint-disable-next-line no-undef
                spyOn(expiryCouponView, 'clicked');
                expiryCouponView.delegateEvents();
                target.click();
                expect(expiryCouponView.clicked).toHaveBeenCalled();
            });

            it('shows the input field when the checkbox is checked', function() {
                // eslint-disable-next-line no-var
                var target = expiryCouponView.$el.find('input[type="checkbox"]');
                target.click();
                expect(expiryCouponView.$el.find('#coupon_expiration_date').is(':visible')).toBe(true);
            });

            it('hides the input field when the checkbox is unchecked', function() {
                /* eslint-disable-next-line no-unused-vars, no-var */
                var target = expiryCouponView.$el.find('input[type="checkbox"]');
                expect(expiryCouponView.$el.find('#coupon_expiration_date')).toHaveAttr('style', 'display: none;');
            });
        });
    });
