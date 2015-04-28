(function (WAIT_TIMEOUT) {
    'use strict';

    describe('VideoControl', function () {
        var state, oldOTBD;

        beforeEach(function () {
            oldOTBD = window.onTouchBasedDevice;
            window.onTouchBasedDevice = jasmine
                .createSpy('onTouchBasedDevice').andReturn(null);
        });

        afterEach(function () {
            $('source').remove();
            state.storage.clear();
            window.Video.previousState = null;
            window.onTouchBasedDevice = oldOTBD;
        });

        describe('constructor', function () {
            beforeEach(function () {
                state = jasmine.initializePlayer();
            });

            it('render the video controls', function () {
                expect($('.video-controls')).toContain(
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

            it('add ARIA attributes to time control', function () {
                var timeControl = $('div.slider > a');

                expect(timeControl).toHaveAttrs({
                    'role': 'slider',
                    'title': 'Video position',
                    'aria-disabled': 'false'
                });

                expect(timeControl).toHaveAttr('aria-valuetext');
            });
        });

        describe('constructor with start-time', function () {
            it(
                'saved position is 0, timer slider and VCR set to start-time',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: 0
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:10 / 1:00');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(10);
                });
            });

            it(
                'saved position is after start-time, ' +
                'timer slider and VCR set to saved position',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: 15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:15 / 1:00');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(15);

                    state.storage.clear();
                });
            });

            it(
                'saved position is negative, ' +
                'timer slider and VCR set to start-time',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: -15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:10 / 1:00');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(10);

                    state.storage.clear();
                });
            });

            it(
                'saved position is not a number, ' +
                'timer slider and VCR set to start-time',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: 'a'
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:10 / 1:00');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(10);

                    state.storage.clear();
                });
            });

            it(
                'saved position is greater than end-time, ' +
                'timer slider and VCR set to start-time',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        savedVideoPosition: 10000
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:10 / 1:00');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(10);

                    state.storage.clear();
                });
            });
        });

        describe('constructor with end-time', function () {
            it(
                'saved position is 0, timer slider and VCR set to 0:00 ' + 
                'and ending at specified end-time',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: 0
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:00 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(0);

                    state.storage.clear();
                });
            });

            it(
                'saved position is after start-time, ' +
                'timer slider and VCR set to saved position',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: 15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:15 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(15);

                    state.storage.clear();
                });
            });

            // TODO: Fix!
            it(
                'saved position is negative, timer slider and VCR set to 0:00',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: -15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:00 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(0);

                    state.storage.clear();
                });
            });

            it(
                'saved position is not a number, ' +
                'timer slider and VCR set to 0:00',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: 'a'
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:00 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(0);

                    state.storage.clear();
                });
            });

            // TODO: Fix!
            it(
                'saved position is greater than end-time, ' +
                'timer slider and VCR set to 0:00',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        end: 20,
                        savedVideoPosition: 10000
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:00 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(0);

                    state.storage.clear();
                });
            });
        });

        describe('constructor with start-time and end-time', function () {
            it(
                'saved position is 0, timer slider and VCR set to appropriate start and end times',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: 0
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:10 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(10);

                    state.storage.clear();
                });
            });

            it(
                'saved position is after start-time, ' +
                'timer slider and VCR set to saved position',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: 15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:15 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(15);

                    state.storage.clear();
                });
            });

            it(
                'saved position is negative, ' +
                'timer slider and VCR set to start-time',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: -15
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:10 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(10);

                    state.storage.clear();
                });
            });

            it(
                'saved position is not a number, ' +
                'timer slider and VCR set to start-time',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: 'a'
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:10 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(10);

                    state.storage.clear();
                });
            });

            it(
                'saved position is greater than end-time, ' +
                'timer slider and VCR set to start-time',
                function ()
            {
                var duration, sliderEl, expectedValue;

                runs(function () {
                    state = jasmine.initializePlayer({
                        start: 10,
                        end: 20,
                        savedVideoPosition: 10000
                    });
                    sliderEl = state.videoProgressSlider.slider;
                    spyOn(state.videoPlayer, 'duration').andReturn(60);
                });

                waitsFor(function () {
                    duration = state.videoPlayer.duration();

                    return isFinite(duration) && duration > 0 &&
                        isFinite(state.videoPlayer.startTime);
                }, 'duration is set', WAIT_TIMEOUT);

                runs(function () {
                    expectedValue = $('.video-controls').find('.vidtime');
                    expect(expectedValue).toHaveText('0:10 / 0:20');

                    expectedValue = sliderEl.slider('option', 'value');
                    expect(expectedValue).toBe(10);

                    state.storage.clear();
                });
            });
        });

        it('Controls height is actual on switch to fullscreen', function () {
            spyOn($.fn, 'height').andCallFake(function (val) {
                return _.isUndefined(val) ? 100: this;
            });

            state = jasmine.initializePlayer();
            $(state.el).trigger('fullscreen');

            expect(state.videoControl.height).toBe(150);
        });

        it('show', function () {
            var controls;

            state = jasmine.initializePlayer();
            controls = state.el.find('.video-controls');
            controls.addClass('is-hidden');

            state.videoControl.show();
            expect(controls).not.toHaveClass('is-hidden');
        });
    });
}).call(this, window.WAIT_TIMEOUT);
