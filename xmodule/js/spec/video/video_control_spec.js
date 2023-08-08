// eslint-disable-next-line no-unused-vars
(function(WAIT_TIMEOUT) {
    'use strict';

    describe('VideoControl', function() {
        // eslint-disable-next-line no-var
        var state, oldOTBD;

        beforeEach(function() {
            oldOTBD = window.onTouchBasedDevice;
            // eslint-disable-next-line no-undef
            window.onTouchBasedDevice = jasmine
                .createSpy('onTouchBasedDevice').and.returnValue(null);
        });

        afterEach(function() {
            $('source').remove();
            state.storage.clear();
            state.videoPlayer.destroy();
            window.onTouchBasedDevice = oldOTBD;
        });

        describe('constructor', function() {
            beforeEach(function() {
                window.VideoState = {};
                // eslint-disable-next-line no-undef
                state = jasmine.initializePlayer();
            });

            it('render the video controls', function() {
                expect($('.video-controls')).toContainElement(
                    [
                        '.slider',
                        'ul.vcr',
                        'a.play',
                        '.vidtime'
                    ].join(',')
                );

                expect($('.video-controls').find('.vidtime'))
                    .toHaveText('0:00 / 0:00');
            });
        });

        describe('constructor with start-time', function() {
            it(
                'saved position is 0, timer slider and VCR set to start-time',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: 0
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();
                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0 && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:10 / 1:00');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(10);
                    }).always(done);
                });

            it(
                'saved position is after start-time, '
                + 'timer slider and VCR set to saved position',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: 15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:15 / 1:00');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(15);

                        state.storage.clear();
                    }).always(done);
                });

            it(
                'saved position is negative, '
                + 'timer slider and VCR set to start-time',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: -15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:10 / 1:00');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(10);

                        state.storage.clear();
                    }).always(done);
                });

            it(
                'saved position is not a number, '
                + 'timer slider and VCR set to start-time',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: 'a'
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:10 / 1:00');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(10);

                        state.storage.clear();
                    }).always(done);
                });

            it(
                'saved position is greater than end-time, '
                + 'timer slider and VCR set to start-time',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: 10000
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:10 / 1:00');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(10);

                        state.storage.clear();
                    }).always(done);
                });
        });

        describe('constructor with end-time', function() {
            it(
                'saved position is 0, timer slider and VCR set to 0:00 '
                + 'and ending at specified end-time',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: 0
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:00 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(0);

                        state.storage.clear();
                    }).always(done);
                });

            it(
                'saved position is after start-time, '
                + 'timer slider and VCR set to saved position',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: 15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:15 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(15);

                        state.storage.clear();
                    }).always(done);
                });

            // TODO: Fix!
            it(
                'saved position is negative, timer slider and VCR set to 0:00',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: -15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:00 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(0);

                        state.storage.clear();
                    }).always(done);
                });

            it(
                'saved position is not a number, '
                + 'timer slider and VCR set to 0:00',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: 'a'
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:00 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(0);

                        state.storage.clear();
                    }).always(done);
                });

            // TODO: Fix!
            it(
                'saved position is greater than end-time, '
                + 'timer slider and VCR set to 0:00',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: 10000
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:00 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(0);

                        state.storage.clear();
                    }).always(done);
                });
        });

        describe('constructor with start-time and end-time', function() {
            it(
                'saved position is 0, timer slider and VCR set to appropriate start and end times',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: 0
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:10 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(10);

                        state.storage.clear();
                    }).always(done);
                });

            it(
                'saved position is after start-time, '
                + 'timer slider and VCR set to saved position',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: 15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:15 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(15);

                        state.storage.clear();
                    }).always(done);
                });

            it(
                'saved position is negative, '
                + 'timer slider and VCR set to start-time',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: -15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:10 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(10);

                        state.storage.clear();
                    }).always(done);
                });

            it(
                'saved position is not a number, '
                + 'timer slider and VCR set to start-time',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: 'a'
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:10 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(10);

                        state.storage.clear();
                    }).always(done);
                });

            it(
                'saved position is greater than end-time, '
                + 'timer slider and VCR set to start-time',
                function(done) {
                    // eslint-disable-next-line no-var
                    var duration, sliderEl, expectedValue;

                    window.VideoState = {};
                    // eslint-disable-next-line no-undef
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: 10000
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    // eslint-disable-next-line no-undef
                    spyOn(state.videoPlayer, 'duration').and.returnValue(60);

                    // eslint-disable-next-line no-undef
                    jasmine.waitUntil(function() {
                        duration = state.videoPlayer.duration();

                        // eslint-disable-next-line no-restricted-globals
                        return isFinite(duration) && duration > 0
                        // eslint-disable-next-line no-restricted-globals
                        && isFinite(state.videoPlayer.startTime);
                    }).then(function() {
                        expectedValue = $('.video-controls').find('.vidtime');
                        expect(expectedValue).toHaveText('0:10 / 0:20');

                        expectedValue = sliderEl.slider('option', 'value');
                        expect(expectedValue).toBe(10);

                        state.storage.clear();
                    }).always(done);
                });
        });

        it('show', function() {
            // eslint-disable-next-line no-var
            var controls;
            // eslint-disable-next-line no-undef
            state = jasmine.initializePlayer();
            controls = state.el.find('.video-controls');
            controls.addClass('is-hidden');

            state.videoControl.show();
            expect(controls).not.toHaveClass('is-hidden');
        });

        it('can destroy itself', function() {
            // eslint-disable-next-line no-undef
            state = jasmine.initializePlayer();
            state.videoControl.destroy();
            expect(state.videoControl).toBeUndefined();
        });

        it('can focus the first control', function(done) {
            // eslint-disable-next-line no-var
            var btnPlay;
            // eslint-disable-next-line no-undef
            state = jasmine.initializePlayer({focusFirstControl: true});
            btnPlay = state.el.find('.video-controls .play');
            // eslint-disable-next-line no-undef
            jasmine.waitUntil(function() {
                return state.el.hasClass('is-initialized');
            }).then(function() {
                expect(btnPlay).toBeFocused();
            }).always(done);
        });
    });
}).call(this, window.WAIT_TIMEOUT);
