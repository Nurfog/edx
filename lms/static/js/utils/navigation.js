/* eslint-disable-next-line no-use-before-define, no-var */
var edx = edx || {},

    Navigation = (function() {
        // eslint-disable-next-line no-var
        var navigation = {

            init: function() {
                if ($('.accordion').length) {
                    navigation.loadAccordion();
                }
            },

            loadAccordion: function() {
                navigation.checkForCurrent();
                navigation.listenForClick();
                navigation.listenForKeypress();
            },

            getActiveIndex: function() {
                // eslint-disable-next-line no-var
                var index = $('.accordion .button-chapter:has(.active)').index('.accordion .button-chapter'),
                    button = null;

                if (index > -1) {
                    button = $('.accordion .button-chapter:eq(' + index + ')');
                }

                return button;
            },

            checkForCurrent: function() {
                // eslint-disable-next-line no-var
                var button = navigation.getActiveIndex();

                navigation.closeAccordions();

                if (button !== null) {
                    navigation.setupCurrentAccordionSection(button);
                }
            },

            listenForClick: function() {
                $('.accordion').on('click', '.button-chapter', function(event) {
                    event.preventDefault();

                    // eslint-disable-next-line no-var
                    var $button = $(event.currentTarget),
                        section = $button.next('.chapter-content-container');

                    navigation.closeAccordions($button, section);
                    navigation.openAccordion($button, section);
                });
            },

            listenForKeypress: function() {
                // eslint-disable-next-line consistent-return
                $('.accordion').on('keydown', '.button-chapter', function(event) {
                    // because we're changing the role of the toggle from an 'a' to a 'button'
                    // we need to ensure it has the same keyboard use cases as a real button.
                    // this is useful for screenreader users primarily.
                    // eslint-disable-next-line eqeqeq
                    if (event.which == 32) { // spacebar
                        event.preventDefault();
                        $(event.currentTarget).trigger('click');
                    } else {
                        return true;
                    }
                });
            },

            closeAccordions: function(button, section) {
                // eslint-disable-next-line no-var
                var menu = $(section).find('.chapter-menu'),
                    // eslint-disable-next-line no-unused-vars
                    toggle;

                $('.accordion .button-chapter').each(function(index, element) {
                    // eslint-disable-next-line no-undef
                    $toggle = $(element);

                    // eslint-disable-next-line no-undef
                    $toggle
                        .removeClass('is-open')
                        .attr('aria-expanded', 'false');

                    // eslint-disable-next-line no-undef
                    $toggle
                        .children('.group-heading')
                        .removeClass('active')
                        .find('.icon')
                        .addClass('fa-caret-right')
                        .removeClass('fa-caret-down');

                    // eslint-disable-next-line no-undef
                    $toggle
                        .next('.chapter-content-container')
                        .removeClass('is-open')
                        .find('.chapter-menu').not(menu)
                        .removeClass('is-open')
                        .slideUp();
                });
            },

            setupCurrentAccordionSection: function(button) {
                // eslint-disable-next-line no-var
                var section = $(button).next('.chapter-content-container');

                navigation.openAccordion(button, section);
            },

            openAccordion: function(button, section) {
                // eslint-disable-next-line no-var
                var $sectionEl = $(section),
                    // eslint-disable-next-line no-unused-vars
                    firstLink = $sectionEl.find('.menu-item').first(),
                    $buttonEl = $(button);

                $buttonEl
                    .addClass('is-open')
                    .attr('aria-expanded', 'true');

                $buttonEl
                    .children('.group-heading')
                    .addClass('active')
                    .find('.icon')
                    .removeClass('fa-caret-right')
                    .addClass('fa-caret-down');

                $sectionEl
                    .addClass('is-open')
                    .find('.chapter-menu')
                    .addClass('is-open')
                    .slideDown();
            }
        };

        return {
            init: navigation.init
        };
    }());

edx.util = edx.util || {};
edx.util.navigation = Navigation;
edx.util.navigation.init();
