/* globals requirejs, requireSerial */
/* eslint-disable quote-props */

(function(requirejs, requireSerial) {
    'use strict';

    var i, specHelpers, testFiles;

    requirejs.config({
        baseUrl: '/base/',
        paths: {
            'gettext': 'common/static/js/test/i18n',
            'codemirror': 'common/static/js/vendor/CodeMirror/codemirror',
            'jquery': 'common/static/common/js/vendor/jquery',
            'jquery-migrate': 'common/static/common/js/vendor/jquery-migrate',
            'jquery.ui': 'common/static/js/vendor/jquery-ui.min',
            'jquery.form': 'common/static/js/vendor/jquery.form',
            'jquery.markitup': 'common/static/js/vendor/markitup/jquery.markitup',
            'jquery.leanModal': 'common/static/js/vendor/jquery.leanModal',
            'jquery.smoothScroll': 'common/static/js/vendor/jquery.smooth-scroll.min',
            'jquery.scrollTo': 'common/static/common/js/vendor/jquery.scrollTo',
            'jquery.timepicker': 'common/static/js/vendor/timepicker/jquery.timepicker',
            'jquery.cookie': 'common/static/js/vendor/jquery.cookie',
            'jquery.qtip': 'common/static/js/vendor/jquery.qtip.min',
            'jquery.fileupload': 'common/static/js/vendor/jQuery-File-Upload/js/jquery.fileupload',
            'jquery.fileupload-process': 'common/static/js/vendor/jQuery-File-Upload/js/jquery.fileupload-process',   // eslint-disable-line max-len
            'jquery.fileupload-validate': 'common/static/js/vendor/jQuery-File-Upload/js/jquery.fileupload-validate',   // eslint-disable-line max-len
            'jquery.iframe-transport': 'common/static/js/vendor/jQuery-File-Upload/js/jquery.iframe-transport',   // eslint-disable-line max-len
            'jquery.inputnumber': 'common/static/js/vendor/html5-input-polyfills/number-polyfill',
            'jquery.immediateDescendents': 'common/static/coffee/src/jquery.immediateDescendents',
            'datepair': 'common/static/js/vendor/timepicker/datepair',
            'date': 'common/static/js/vendor/date',
            'text': 'common/static/js/vendor/requirejs/text',
            'underscore': 'common/static/common/js/vendor/underscore',
            'underscore.string': 'common/static/common/js/vendor/underscore.string',
            'backbone': 'common/static/common/js/vendor/backbone',
            'backbone.associations': 'common/static/js/vendor/backbone-associations-min',
            'backbone.paginator': 'common/static/common/js/vendor/backbone.paginator',
            'tinymce': 'common/static/js/vendor/tinymce/js/tinymce/tinymce.full.min',
            'jquery.tinymce': 'common/static/js/vendor/tinymce/js/tinymce/jquery.tinymce',
            'xmodule': 'common/lib/xmodule/xmodule/js/src/xmodule',
            'xblock/cms.runtime.v1': 'cms/static/cms/js/xblock/cms.runtime.v1',
            'xblock': 'cms/static/common/js/xblock',
            'utility': 'common/static/js/src/utility',
            'sinon': 'common/static/common/js/vendor/sinon',
            'squire': 'common/static/common/js/vendor/Squire',
            'draggabilly': 'common/static/js/vendor/draggabilly',
            'domReady': 'common/static/js/vendor/domReady',
            'URI': 'common/static/js/vendor/URI.min',
            'mathjax': '//cdnjs.cloudflare.com/ajax/libs/mathjax/2.7.1/MathJax.js?config=TeX-MML-AM_SVG&delayStartupUntil=configured',   // eslint-disable-line max-len
            'youtube': '//www.youtube.com/player_api?noext',
            'coffee/src/ajax_prefix': 'common/static/coffee/src/ajax_prefix'
        },
        shim: {
            'gettext': {
                exports: 'gettext'
            },
            'date': {
                exports: 'Date'
            },
            'jquery.ui': {
                deps: ['jquery'],
                exports: 'jQuery.ui'
            },
            'jquery.form': {
                deps: ['jquery'],
                exports: 'jQuery.fn.ajaxForm'
            },
            'jquery.markitup': {
                deps: ['jquery'],
                exports: 'jQuery.fn.markitup'
            },
            'jquery.leanModal': {
                deps: ['jquery'],
                exports: 'jQuery.fn.leanModal'
            },
            'jquery.smoothScroll': {
                deps: ['jquery'],
                exports: 'jQuery.fn.smoothScroll'
            },
            'jquery.scrollTo': {
                deps: ['jquery'],
                exports: 'jQuery.fn.scrollTo'
            },
            'jquery.cookie': {
                deps: ['jquery'],
                exports: 'jQuery.fn.cookie'
            },
            'jquery.qtip': {
                deps: ['jquery'],
                exports: 'jQuery.fn.qtip'
            },
            'jquery.fileupload': {
                deps: ['jquery.ui', 'jquery.iframe-transport'],
                exports: 'jQuery.fn.fileupload'
            },
            'jquery.fileupload-process': {
                deps: ['jquery.fileupload']
            },
            'jquery.fileupload-validate': {
                deps: ['jquery.fileupload']
            },
            'jquery.inputnumber': {
                deps: ['jquery'],
                exports: 'jQuery.fn.inputNumber'
            },
            'jquery.tinymce': {
                deps: ['jquery', 'tinymce'],
                exports: 'jQuery.fn.tinymce'
            },
            'datepair': {
                deps: ['jquery.ui', 'jquery.timepicker']
            },
            'underscore': {
                exports: '_'
            },
            'backbone': {
                deps: ['underscore', 'jquery'],
                exports: 'Backbone'
            },
            'backbone.associations': {
                deps: ['backbone'],
                exports: 'Backbone.Associations'
            },
            'backbone.paginator': {
                deps: ['backbone'],
                exports: 'Backbone.PageableCollection'
            },
            'youtube': {
                exports: 'YT'
            },
            'codemirror': {
                exports: 'CodeMirror'
            },
            'tinymce': {
                exports: 'tinymce'
            },
            'mathjax': {
                exports: 'MathJax',
                init: function() {
                    window.MathJax.Hub.Config({
                        tex2jax: {
                            inlineMath: [['\\(', '\\)'], ['[mathjaxinline]', '[/mathjaxinline]']],
                            displayMath: [['\\[', '\\]'], ['[mathjax]', '[/mathjax]']]
                        }
                    });
                    window.MathJax.Hub.Configured();
                }
            },
            'URI': {
                exports: 'URI'
            },
            'xmodule': {
                exports: 'XModule'
            },
            'sinon': {
                exports: 'sinon'
            },
            'cms/static/common/js/spec_helpers/jasmine-extensions': {
                deps: ['jquery']
            },
            'cms/static/common/js/spec_helpers/jasmine-stealth': {
                deps: ['underscore', 'underscore.string']
            },
            'cms/static/common/js/spec_helpers/jasmine-waituntil': {
                deps: ['jquery']
            },
            'xblock/core': {
                exports: 'XBlock',
                deps: ['jquery', 'jquery.immediateDescendents']
            },
            'xblock/runtime.v1': {
                exports: 'XBlock',
                deps: ['xblock/core']
            },
            'cms/static/cms/js/main': {
                deps: ['coffee/src/ajax_prefix']
            },
            'coffee/src/ajax_prefix': {
                deps: ['jquery']
            }
        }
    });

    jasmine.getFixtures().fixturesPath += 'coffee/fixtures';

    testFiles = [
        'cms/static/coffee/spec/views/assets_spec',
        'cms/static/js/spec/video/translations_editor_spec',
        'cms/static/js/spec/video/file_uploader_editor_spec',
        'cms/static/js/spec/models/group_configuration_spec'
    ];

    i = 0;

    while (i < testFiles.length) {
        testFiles[i] = '/base/' + testFiles[i] + '.js';
        i++;
    }

    specHelpers = [
        'cms/static/common/js/spec_helpers/jasmine-extensions',
        'cms/static/common/js/spec_helpers/jasmine-stealth',
        'cms/static/common/js/spec_helpers/jasmine-waituntil'
    ];

    requireSerial(specHelpers.concat(testFiles), function() {
        return window.__karma__.start();  // eslint-disable-line no-underscore-dangle
    });
}).call(this, requirejs, requireSerial);
