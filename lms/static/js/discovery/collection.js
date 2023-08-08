(function(define) {
    define([
        'backbone',
        'js/discovery/models/course_card'
    ], function(Backbone, CourseCard) {
        'use strict';

        return Backbone.Collection.extend({

            model: CourseCard,
            pageSize: 20,
            totalCount: 0,
            latestModelsCount: 0,
            searchTerm: '',
            selectedFacets: {},
            facets: {},
            page: 0,
            url: '/search/course_discovery/',
            fetchXhr: null,

            performSearch: function(searchTerm, facets) {
                // eslint-disable-next-line no-unused-expressions
                this.fetchXhr && this.fetchXhr.abort();
                this.searchTerm = searchTerm || '';
                this.selectedFacets = facets || {};
                // eslint-disable-next-line no-var
                var data = this.preparePostData(0);
                this.resetState();
                this.fetchXhr = this.fetch({
                    data: data,
                    type: 'POST',
                    // eslint-disable-next-line no-unused-vars
                    success: function(self, xhr) {
                        self.trigger('search');
                    },
                    // eslint-disable-next-line no-unused-vars
                    error: function(self, xhr) {
                        self.trigger('error');
                    }
                });
            },

            loadNextPage: function() {
                // eslint-disable-next-line no-unused-expressions
                this.fetchXhr && this.fetchXhr.abort();
                // eslint-disable-next-line no-var
                var data = this.preparePostData(this.page + 1);
                this.fetchXhr = this.fetch({
                    data: data,
                    type: 'POST',
                    // eslint-disable-next-line no-unused-vars
                    success: function(self, xhr) {
                        self.page += 1;
                        self.trigger('next');
                    },
                    // eslint-disable-next-line no-unused-vars
                    error: function(self, xhr) {
                        self.trigger('error');
                    },
                    add: true,
                    reset: false,
                    remove: false
                });
            },

            preparePostData: function(pageNumber) {
                // eslint-disable-next-line no-var
                var data = {
                    search_string: this.searchTerm,
                    page_size: this.pageSize,
                    page_index: pageNumber
                };
                if (this.selectedFacets.length > 0) {
                    this.selectedFacets.each(function(facet) {
                        data[facet.get('type')] = facet.get('query');
                    });
                }
                return data;
            },

            parse: function(response) {
                // eslint-disable-next-line no-var
                var results = response.results || [];
                this.latestModelsCount = results.length;
                this.totalCount = response.total;
                if (typeof response.aggs !== 'undefined') {
                    this.facets = response.aggs;
                } else {
                    this.facets = [];
                }
                // eslint-disable-next-line no-undef
                return _.map(results, function(result) {
                    return result.data;
                });
            },

            resetState: function() {
                this.reset();
                this.page = 0;
                this.totalCount = 0;
                this.latestModelsCount = 0;
            },

            hasNextPage: function() {
                return this.totalCount - ((this.page + 1) * this.pageSize) > 0;
            },

            latestModels: function() {
                return this.last(this.latestModelsCount);
            }

        });
    });
// eslint-disable-next-line no-undef
}(define || RequireJS.define));
