(function() {
    'use strict';

    describe('VideoFullScreen', function() {
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
                // eslint-disable-next-line no-undef
                state = jasmine.initializePlayer();
                // eslint-disable-next-line no-undef
                jasmine.mockFullscreenAPI();
            });

            it('renders the fullscreen control', function() {
                expect($('.add-fullscreen')).toExist();
                expect(state.videoFullScreen.fullScreenState).toBe(false);
            });

            it('correctly adds ARIA attributes to fullscreen control', function() {
                // eslint-disable-next-line no-var
                var $fullScreenControl = $('.add-fullscreen');

                expect($fullScreenControl).toHaveAttrs({
                    'aria-disabled': 'false'
                });
            });

            it('correctly triggers the event handler to toggle fullscreen mode', function() {
                // eslint-disable-next-line no-undef
                spyOn(state.videoFullScreen, 'exit');
                // eslint-disable-next-line no-undef
                spyOn(state.videoFullScreen, 'enter');

                state.videoFullScreen.fullScreenState = false;
                state.videoFullScreen.toggle();
                expect(state.videoFullScreen.enter).toHaveBeenCalled();

                state.videoFullScreen.fullScreenState = true;
                state.videoFullScreen.toggle();
                expect(state.videoFullScreen.exit).toHaveBeenCalled();
            });

            it('correctly updates ARIA on state change', function() {
                // eslint-disable-next-line no-var
                var $fullScreenControl = $('.add-fullscreen');
                $fullScreenControl.click();
                expect($fullScreenControl).toHaveAttrs({
                    'aria-disabled': 'false'
                });
                $fullScreenControl.click();
                expect($fullScreenControl).toHaveAttrs({
                    'aria-disabled': 'false'
                });
            });

            it('correctly can out of fullscreen by pressing esc', function() {
                // eslint-disable-next-line no-undef
                spyOn(state.videoCommands, 'execute');
                // eslint-disable-next-line no-var
                var esc = $.Event('keyup');
                esc.keyCode = 27;
                state.isFullScreen = true;
                $(document).trigger(esc);
                expect(state.videoCommands.execute).toHaveBeenCalledWith('toggleFullScreen');
            });

            it('can update video dimensions on state change', function() {
                state.videoFullScreen.enter();
                expect(state.resizer.setMode).toHaveBeenCalledWith('both');
                state.videoFullScreen.exit();
                expect(state.resizer.setMode).toHaveBeenCalledWith('width');
            });

            it('can destroy itself', function() {
                state.videoFullScreen.destroy();
                expect($('.add-fullscreen')).not.toExist();
                expect(state.videoFullScreen).toBeUndefined();
            });
        });

        it('Controls height is actual on switch to fullscreen', function() {
            // eslint-disable-next-line no-undef
            spyOn($.fn, 'height').and.callFake(function(val) {
                // eslint-disable-next-line no-undef
                return _.isUndefined(val) ? 100 : this;
            });

            // eslint-disable-next-line no-undef
            state = jasmine.initializePlayer();

            state.videoFullScreen.enter();
            expect(state.videoFullScreen.height).toBe(150);
            state.videoFullScreen.exit();
        });
    });
}).call(this);
