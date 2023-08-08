(function(require) {
    require(
        ['video/00_sjson.js'],
        function(Sjson) {
            describe('Sjson', function() {
                /* eslint-disable-next-line no-undef, no-var */
                var data = jasmine.stubbedCaption,
                    sjson;
                // eslint-disable-next-line no-var
                var videoStops = [0, 3120, 6270, 8490, 21620, 24920];
                // eslint-disable-next-line no-var
                var OUT_OF_BOUNDS_STOP = 10024920;

                beforeEach(function() {
                    sjson = new Sjson(data);
                });

                it('returns captions', function() {
                    expect(sjson.getCaptions()).toEqual(data.text);
                });

                it('returns start times', function() {
                    expect(sjson.getStartTimes()).toEqual(data.start);
                });

                it('returns correct length', function() {
                    expect(sjson.getSize()).toEqual(data.text.length);
                });

                it('search returns a correct caption index', function() {
                    expect(sjson.search(videoStops[0])).toEqual(0);
                    expect(sjson.search(videoStops[1])).toEqual(1);
                    expect(sjson.search(videoStops[2])).toEqual(2);
                    expect(sjson.search(videoStops[3])).toEqual(2);
                    expect(sjson.search(videoStops[4])).toEqual(4);
                    expect(sjson.search(videoStops[5])).toEqual(5);
                });

                it('search returns the last entry for a value outside the bounds of the array', function() {
                    expect(sjson.search(OUT_OF_BOUNDS_STOP)).toEqual(sjson.getCaptions().length - 1);
                });

                it('search returns the first entry for a negative index in the array', function() {
                    expect(sjson.search(-1)).toEqual(0);
                });

                it('search only searches through a subrange of times if start / end times are specified', function() {
                    // eslint-disable-next-line no-var
                    var start = videoStops[2] - 100;
                    // eslint-disable-next-line no-var
                    var end = videoStops[5] - 100;
                    // eslint-disable-next-line no-var
                    var results = sjson.filter(start, end);
                    // eslint-disable-next-line no-var
                    var expectedLength = results.captions.length - 1;

                    expect(sjson.search(videoStops[0], start, end)).toEqual(0);
                    expect(sjson.search(videoStops[1], start, end)).toEqual(0);
                    expect(sjson.search(videoStops[2], start, end)).toEqual(0);
                    expect(sjson.search(videoStops[3], start, end)).toEqual(0);
                    expect(sjson.search(OUT_OF_BOUNDS_STOP, start, end)).toEqual(expectedLength);
                });

                it('filters results correctly given a start and end time', function() {
                    // eslint-disable-next-line no-var
                    var start = videoStops[1] - 100;
                    // eslint-disable-next-line no-var
                    var end = videoStops[4] - 100;
                    // eslint-disable-next-line no-var
                    var results = sjson.filter(start, end);

                    expect(results.start.length).toEqual(3);
                    expect(results.captions.length).toEqual(3);
                });
            });
        });
}(require));
