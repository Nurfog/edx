// eslint-disable-next-line no-undef
define(['backbone'], function(Backbone) {
    // eslint-disable-next-line no-var
    var Course = Backbone.Model.extend({
        defaults: {
            name: ''
        },
        /* eslint-disable-next-line consistent-return, no-unused-vars */
        validate: function(attrs, options) {
            if (!attrs.name) {
                return gettext('You must specify a name');
            }
        }
    });
    return Course;
});
