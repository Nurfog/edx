// eslint-disable-next-line no-undef
define(['jquery'], function($) {
    // Trigger "Change" event on "Enter" keyup event
    // eslint-disable-next-line no-var
    var triggerChangeEventOnEnter = function(e) {
        // eslint-disable-next-line eqeqeq
        if (e.which == 13) {
            $(this).trigger('change').blur();
        }
    };

    return triggerChangeEventOnEnter;
});
