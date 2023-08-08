/* eslint-disable-next-line no-shadow-restricted-names, no-unused-vars */
(function(define, undefined) {
    'use strict';

    define([
        'gettext',
        'jquery',
        'underscore',
        'backbone',
        'edx-ui-toolkit/js/utils/html-utils',
        'text!templates/student_account/account_settings_section.underscore'
    ], function(gettext, $, _, Backbone, HtmlUtils, sectionTemplate) {
        // eslint-disable-next-line no-var
        var AccountSectionView = Backbone.View.extend({

            initialize: function(options) {
                this.options = options;
                _.bindAll(this, 'render', 'renderFields');
            },

            render: function() {
                HtmlUtils.setHtml(
                    this.$el,
                    HtmlUtils.template(sectionTemplate)({
                        HtmlUtils: HtmlUtils,
                        sections: this.options.sections,
                        tabName: this.options.tabName,
                        tabLabel: this.options.tabLabel
                    })
                );

                this.renderFields();
            },

            renderFields: function() {
                // eslint-disable-next-line no-var
                var view = this;

                _.each(view.$('.' + view.options.tabName + '-section-body'), function(sectionEl, index) {
                    _.each(view.options.sections[index].fields, function(field) {
                        $(sectionEl).append(field.view.render().el);
                    });
                });
                return this;
            }
        });

        return AccountSectionView;
    });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
