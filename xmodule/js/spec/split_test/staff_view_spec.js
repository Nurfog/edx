describe('Tests for split_test staff view switching', function() {
    /* eslint-disable-next-line camelcase, no-unused-vars, no-var */
    var ab_module;
    // eslint-disable-next-line no-var
    var $elem;

    beforeEach(function() {
        loadFixtures('split_test_staff.html');
        $elem = $('#split-test');
        // eslint-disable-next-line no-undef
        window.XBlock = jasmine.createSpyObj('XBlock', ['initializeBlocks']);
        /* eslint-disable-next-line camelcase, no-undef */
        ab_module = ABTestSelector(null, $elem);
    });

    afterEach(function() {
        delete window.XBlock;
    });

    it('test that we have only one visible condition', function() {
        // eslint-disable-next-line no-var
        var containers = $elem.find('.split-test-child-container').length;
        /* eslint-disable-next-line camelcase, no-var */
        var conditions_shown = $elem.find('.split-test-child-container .condition-text').length;
        expect(containers).toEqual(1);
        expect(conditions_shown).toEqual(1);
        expect(XBlock.initializeBlocks).toHaveBeenCalled();
    });

    it('test that the right child is visible when selected', function() {
        // eslint-disable-next-line no-var
        var groups = ['0', '1', '2'];

        // eslint-disable-next-line no-var
        for (var i = 0; i < groups.length; i++) {
            /* eslint-disable-next-line camelcase, no-var */
            var to_select = groups[i];
            $elem.find('.split-test-select').val(to_select).change();
            /* eslint-disable-next-line camelcase, no-var */
            var child_text = $elem.find('.split-test-child-container .condition-text').text();
            expect(child_text).toContain(to_select);
            expect(XBlock.initializeBlocks).toHaveBeenCalled();
        }
    });
});
