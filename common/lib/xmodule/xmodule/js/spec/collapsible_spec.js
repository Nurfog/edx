(function (undefined) {
    'use strict';

    describe('Collapsible', function () {
        var el, html, html_custom,
            initialize = function (template) {
                setFixtures(template);
                el = $('.collapsible');
                Collapsible.setCollapsibles(el);
            },
            disableFx = function () {
                $.fx.off = true;
            },
            enableFx = function () {
                $.fx.off = false;
            };

        beforeEach(function () {
            html = '' +
                '<section class="collapsible">' +
                    '<div class="shortform">shortform message</div>' +
                    '<div class="longform">' +
                        '<p>longform is visible</p>' +
                    '</div>' +
                '</section>';
            html_custom = '' +
                '<section class="collapsible">' +
                    '<div ' +
                        'class="shortform-custom" ' +
                        'data-open-text="Show shortform-custom" ' +
                        'data-close-text="Hide shortform-custom"' +
                    '>shortform message</div>' +
                    '<div class="longform">' +
                        '<p>longform is visible</p>' +
                    '</div>' +
                '</section>';
        });

        describe('setCollapsibles', function () {
            it('Default container initialized correctly', function () {
                initialize(html);

                expect(el.find('.shortform')).toContain('.full-top');
                expect(el.find('.shortform')).toContain('.full-bottom');
                expect(el.find('.longform')).toBeHidden();
            });

            it('Custom container initialized correctly', function () {
                initialize(html_custom);

                expect(el.find('.shortform-custom')).toContain('.full-custom');
                expect(el.find('.full-custom')).toHaveText('Show shortform-custom');
                expect(el.find('.longform')).toBeHidden();
            });
        });

        describe('toggleFull', function () {
            var assertChanges = function (state, anchorsElClass, showText, hideText) {
                var anchors, text;

                if (state == null) {
                    state = 'closed';
                }

                anchors = el.find('.' + anchorsElClass);

                if (state === 'closed') {
                    expect(el.find('.longform')).toBeHidden();
                    expect(el).not.toHaveClass('open');
                    text = showText;
                } else {
                    expect(el.find('.longform')).toBeVisible();
                    expect(el).toHaveClass('open');
                    text = hideText;
                }

                $.each(anchors, function (index, el) {
                    expect(el).toHaveText(text);
                });
            };

            beforeEach(function () {
                disableFx();
            });

            afterEach(function () {
                enableFx();
            });

            it('Default container', function () {
                var item;

                initialize(html);
                item =  el.find('.full').get(0);

                item.click();
                assertChanges('opened', 'full', 'See full output', 'Hide output');

                item.click();
                assertChanges('closed', 'full', 'See full output', 'Hide output');
            });

            it('Custom container', function () {
                var item;

                initialize(html_custom);
                item =  el.find('.full-custom').get(0);

                item.click();
                assertChanges('opened', 'full-custom', 'Show shortform-custom', 'Hide shortform-custom');

                item.click();
                assertChanges('closed', 'full-custom', 'Show shortform-custom', 'Hide shortform-custom');
            });
        });
    });
}).call(this);
