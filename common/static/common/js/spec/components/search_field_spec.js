// eslint-disable-next-line no-undef
define([
    'underscore',
    'URI',
    'edx-ui-toolkit/js/utils/spec-helpers/ajax-helpers',
    'edx-ui-toolkit/js/pagination/paging-collection',
    'common/js/components/views/search_field'
], function(_, URI, AjaxHelpers, PagingCollection, SearchFieldView) {
    'use strict';

    describe('SearchFieldView', function() {
        // eslint-disable-next-line no-var
        var searchFieldView,
            mockUrl = '/api/mock_collection';

        // eslint-disable-next-line no-var
        var newCollection = function(size, perPage) {
            // eslint-disable-next-line no-var
            var results = _.map(_.range(size), function(i) { return {foo: i}; });
            // eslint-disable-next-line no-var
            var TestPagingCollection = PagingCollection.extend({
                state: {
                    pageSize: 5
                }
            });

            // eslint-disable-next-line no-var
            var collection = new TestPagingCollection({
                count: results.length,
                num_pages: Math.ceil(results.length / perPage),
                page: 1,
                results: _.first(results, perPage)
            }, {parse: true});

            collection.url = mockUrl;
            return collection;
        };

        // eslint-disable-next-line no-var
        var createSearchFieldView = function(options) {
            options = _.extend(
                {
                    type: 'test',
                    collection: newCollection(5, 4),
                    el: $('.test-search')
                },
                options || {}
            );
            return new SearchFieldView(options);
        };

        // eslint-disable-next-line no-var
        var assertQueryParams = function(request, expectedParameters) {
            // eslint-disable-next-line no-var
            var urlParams = new URI(request.url).query(true);
            _.each(expectedParameters, function(value, key) {
                expect(urlParams[key]).toBe(value);
            });
        };

        // eslint-disable-next-line no-var
        var assertNotInQueryParams = function(request, param) {
            // eslint-disable-next-line no-var
            var urlParams = new URI(request.url).query(true);
            // eslint-disable-next-line no-prototype-builtins
            return !urlParams.hasOwnProperty(param);
        };

        beforeEach(function() {
            setFixtures('<section class="test-search"></section>');
        });

        it('correctly displays itself', function() {
            searchFieldView = createSearchFieldView().render();
            expect(searchFieldView.$('.search-field').val(), '');
            expect(searchFieldView.$('.action-clear')).toHaveClass('is-hidden');
        });

        it('can display with an initial search string', function() {
            searchFieldView = createSearchFieldView({
                searchString: 'foo'
            }).render();
            expect(searchFieldView.$('.search-field').val(), 'foo');
        });

        it('refreshes the collection when performing a search', function() {
            // eslint-disable-next-line no-var
            var requests = AjaxHelpers.requests(this);
            searchFieldView = createSearchFieldView().render();
            searchFieldView.$('.search-field').val('foo');
            searchFieldView.$('.action-search').click();
            assertQueryParams(requests[0], {
                page: '1',
                page_size: '5',
                text_search: 'foo'
            });

            AjaxHelpers.respondWithJson(requests, {
                count: 10,
                page: 1,
                num_pages: 1,
                results: []
            });
            expect(searchFieldView.$('.search-field').val(), 'foo');
        });

        it('can clear the search', function() {
            // eslint-disable-next-line no-var
            var requests = AjaxHelpers.requests(this);
            searchFieldView = createSearchFieldView({
                searchString: 'foo'
            }).render();
            searchFieldView.$('.action-clear').click();
            assertNotInQueryParams('text_search');

            AjaxHelpers.respondWithJson(requests, {
                count: 10,
                page: 1,
                num_pages: 1,
                results: []
            });
            expect(searchFieldView.$('.search-field').val(), '');
            expect(searchFieldView.$('.action-clear')).toHaveClass('is-hidden');
        });
    });
});
