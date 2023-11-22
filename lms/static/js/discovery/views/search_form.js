(function(define) {
    define(['jquery', 'backbone', 'gettext'], function($, Backbone, gettext) {
        'use strict';

        return Backbone.View.extend({

            el: '#discovery-form',
            events: {
                'submit form': 'submitForm'
            },

            initialize: function() {
                this.$searchField = this.$el.find('input');
                this.$searchButton = this.$el.find('button');
                this.$message = this.$el.find('#discovery-message');
                this.$loadingIndicator = this.$el.find('#loading-indicator');
            },

            submitForm: function(event) {
                event.preventDefault();
                var query = this.$searchField.val();
                $('#search-query-display').text('Search Query: ' + query);
                this.doSearch();
            },

            doSearch: function(term) {
                if (term !== undefined) {
                    this.$searchField.val(term);
                } else {
                    term = this.$searchField.val();
                }
                this.trigger('search', $.trim(term));
            },

            clearSearch: function() {
                this.$searchField.val('');
            },

            showLoadingIndicator: function() {
                this.$loadingIndicator.removeClass('hidden');
            },

            hideLoadingIndicator: function() {
                this.$loadingIndicator.addClass('hidden');
            },

           
            showFoundMessage: function(count, query) {
                var msg;
                if (count === 1) {
                    msg = interpolate(
                        gettext('1 result found for "%s"'),
                        [_.escape(query)]
                    );
                } else {
                    msg = interpolate(
                        gettext('%s results found for "%s"'),
                        [count, _.escape(query)]
                    );
                }
                this.$message.html(msg);
            },
            

            showNotFoundMessage: function(term) {
                var msg = interpolate(
                    gettext('We couldn\'t find any results for "%s".'),
                    [_.escape(term)]
                );
                this.$message.html(msg);
                this.clearSearch();
            },

            showErrorMessage: function(error) {
                this.$message.text(gettext(error || 'There was an error, try searching again.'));
            }

        });
    });
}(define || RequireJS.define));
