(function() {
    // eslint-disable-next-line no-var
    var update = function() {
        // Whenever a value changes create a new serialized version of this
        // problem's inputs and set the hidden input field's value to equal it.
        // eslint-disable-next-line no-var
        var parent = $(this).closest('section.choicetextinput');
        // find the closest parent problems-wrapper and use that as the problem
        // grab the input id from the input
        // real_input is the hidden input field
        /* eslint-disable-next-line camelcase, no-var */
        var $real_input = $('input.choicetextvalue', parent);
        /* eslint-disable-next-line camelcase, no-var */
        var $all_inputs = $('input.ctinput', parent);
        /* eslint-disable-next-line camelcase, no-var */
        var user_inputs = {};
        $($all_inputs).each(function(index, elt) {
            // eslint-disable-next-line no-var
            var $node = $(elt);
            // eslint-disable-next-line no-var
            var name = $node.attr('id');
            // eslint-disable-next-line no-var
            var val = $node.val();
            /* eslint-disable-next-line camelcase, no-var */
            var radio_value = $node.attr('value');
            // eslint-disable-next-line no-var
            var type = $node.attr('type');
            /* eslint-disable-next-line camelcase, no-var */
            var is_checked = $node.attr('checked');
            if (type === 'radio' || type === 'checkbox') {
                // eslint-disable-next-line camelcase
                if (is_checked === 'checked' || is_checked === 'true') {
                    // eslint-disable-next-line camelcase
                    user_inputs[name] = radio_value;
                }
            } else {
                // eslint-disable-next-line camelcase
                user_inputs[name] = val;
            }
        });
        /* eslint-disable-next-line camelcase, no-var */
        var val_string = JSON.stringify(user_inputs);
        // this is what gets submitted as the answer, we deserialize it later
        // eslint-disable-next-line camelcase
        $real_input.val(val_string);
    };

    /* eslint-disable-next-line camelcase, no-var */
    var check_parent = function(event) {
        // This looks for the containing choice of a textinput
        // and sets it to be checked.
        // eslint-disable-next-line no-var
        var $elt = $(event.target);
        /* eslint-disable-next-line camelcase, no-var */
        var parent_container = $elt.closest('section[id^="forinput"]');
        /* eslint-disable-next-line camelcase, no-var */
        var choice = parent_container.find("input[type='checkbox'], input[type='radio']");
        choice.attr('checked', 'checked');
        choice.change();
        // need to check it then trigger the change event
    };

    /* eslint-disable-next-line camelcase, no-var */
    var imitate_label = function(event) {
        // This causes a section to check and uncheck
        // a radiobutton/checkbox whenever a user clicks on it
        // If the button/checkbox is disabled, nothing happens
        // eslint-disable-next-line no-var
        var $elt = $(event.target);
        /* eslint-disable-next-line camelcase, no-var */
        var parent_container = $elt.closest('section[id^="forinput"]');
        /* eslint-disable-next-line camelcase, no-var */
        var choice = parent_container.find("input[type='checkbox'], input[type='radio']");
        if (choice.attr('type') === 'radio') {
            choice.attr('checked', 'checked');
        } else {
            if (choice.attr('checked')) {
                choice.prop('checked', false);
            } else {
                choice.prop('checked', true);
            }
        }
        choice.change();
        update();
    };
    // eslint-disable-next-line no-var
    var $choices = $('.mock_label');
    // eslint-disable-next-line no-var
    var $inputs = $('.choicetextinput .ctinput');
    /* eslint-disable-next-line camelcase, no-var */
    var $text_inputs = $('.choicetextinput .ctinput[type="text"]');
    // update on load
    $inputs.each(update);
    // and on every change
    // This allows text inside of choices to behave as if they were part of
    // a label for the choice's button/checkbox
    $choices.click(imitate_label);
    $inputs.bind('change', update);
    // eslint-disable-next-line camelcase
    $text_inputs.click(check_parent);
}).call(this);
