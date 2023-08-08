import * as TabsModel from 'js/models/explicit_url';
import * as TabsEditView from 'js/views/tabs';
import * as xmoduleLoader from 'xmodule';
import './base';
import 'cms/js/main';
import 'xblock/cms.runtime.v1';
import 'xmodule/js/src/xmodule'; // Force the XBlockToXModuleShim to load for Static Tabs

// eslint-disable-next-line no-unused-expressions
'use strict';
export default function EditTabsFactory(courseLocation, explicitUrl) {
    xmoduleLoader.done(function() {
        // eslint-disable-next-line no-var
        var model = new TabsModel({
                id: courseLocation,
                explicit_url: explicitUrl
            }),
            editView;

        // eslint-disable-next-line no-unused-vars
        editView = new TabsEditView({
            el: $('.tab-list'),
            model: model,
            mast: $('.wrapper-mast')
        });
    });
}

export {EditTabsFactory};
