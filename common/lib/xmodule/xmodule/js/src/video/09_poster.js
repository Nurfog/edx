(function (define) {

define(
'video/09_poster.js',
[], function () {
    /**
     * VideoPoster module.
     * @exports video/09_play_skip_control.js
     * @constructor
     * @param {jquery Element} container
     * @param {Object} options
     * @return {jquery Promise}
     */
    var VideoPoster = function (container, options) {
        if (!(this instanceof VideoPoster)) {
            return new VideoPoster(state);
        }

        _.bindAll(this, 'onClick', 'destroy');
        this.dfd = $.Deferred();
        this.container = container;
        this.options = options || {};
        this.initialize();
    };

    VideoPoster.moduleName = 'Poster';
    VideoPoster.prototype = {
        template: _.template([
            '<div class="poster-<%= type %> poster" ',
                'style="background-image: url(<%= url %>)">',
                '<span tabindex="0" class="btn-play" aria-label="',
                    gettext('Play video'), '"></span>',
            '</div>'
        ].join('')),

        initialize: function () {
            if (!this.options.poster) {
                return;
            }
            this.el = $(this.template({
                url: this.options.poster.url,
                type: this.options.poster.type
            }));
            this.render();
            this.bindHandlers();
        },

        bindHandlers: function () {
            this.el.on('click', this.onClick);
            this.container.on('play destroy', this.destroy);
        },

        render: function () {
            this.container.find('.video-player').append(this.el);
        },

        onClick: function () {
            if (_.isFunction(this.options.onClick)) {
                this.options.onClick();
            }
        },

        destroy: function () {
            this.container.off('play destroy', this.destroy);
            this.el.remove();
        }
    };

    return VideoPoster;
});

}(RequireJS.define));
