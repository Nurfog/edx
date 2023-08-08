(function() {
    // eslint-disable-next-line lines-around-directive
    'use strict';

    describe('VideoSocialSharingHandler', function() {
        /* eslint-disable-next-line no-unused-vars, no-var */
        var state;

        beforeEach(function() {
            // eslint-disable-next-line no-undef
            state = jasmine.initializePlayer('video_all.html');
            // eslint-disable-next-line no-undef
            window.analytics = jasmine.createSpyObj('analytics', ['track']);
        });

        afterAll(() => delete window.analytics);

        describe('clicking social share fires an analytics event', function() {
            const testCases = [
                // eslint-disable-next-line object-curly-spacing
                { source: 'twitter' },
                // eslint-disable-next-line object-curly-spacing
                { source: 'facebook' },
                // eslint-disable-next-line object-curly-spacing
                { source: 'linkedin' },
            ];
            /* eslint-disable-next-line object-curly-spacing, no-undef */
            _.each(testCases, ({ source }) => {
                it(source, () => {
                    // eslint-disable-next-line no-var
                    var siteShareButton = $(`.social-share-link[data-source="${source}"]`);
                    expect(siteShareButton.length).toEqual(1);

                    siteShareButton.trigger('click');

                    expect(window.analytics.track).toHaveBeenCalledWith(
                        'edx.social.video.share_button.clicked',
                        {
                            source: source,
                            video_block_id: 'block-v1:coursekey+type@video+block@000000000000000000',
                            course_id: 'course-v1:someOrg+thisCOurse+runAway',
                        }
                    );
                });
            });
        });
    });
}).call(this);
