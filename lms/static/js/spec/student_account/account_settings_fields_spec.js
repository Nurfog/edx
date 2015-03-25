define(['backbone', 'jquery', 'underscore', 'js/common_helpers/ajax_helpers', 'js/common_helpers/template_helpers',
        'js/student_account/views/account_settings_fields',
        'js/student_account/models/user_account_model',
        'string_utils'],
    function (Backbone, $, _, AjaxHelpers, TemplateHelpers, FieldViews, UserAccountModel) {
        'use strict';

        describe("edx.FieldViews", function () {

            var requests,
                timerCallback;

            var fieldViewClasses = [
                FieldViews.ReadonlyFieldView,
                FieldViews.TextFieldView,
                FieldViews.EmailFieldView,
                FieldViews.DropdownFieldView,
                FieldViews.LinkFieldView,
                FieldViews.PasswordFieldView,
                FieldViews.TextareaFieldView
            ];

            var USERNAME = 'Legolas',
                FULLNAME = 'Legolas Thranduil',
                EMAIL = 'legolas@woodland.middlearth',
                LANGUAGE = [['si', 'sindarin'], ['el', 'elvish']],
                COUNTRY = 'woodland',
                DATE_JOINED = '',
                GENDER = 'female',
                GOALS = '',
                LEVEL_OF_EDUCATION = null,
                MAILING_ADDRESS = '',
                YEAR_OF_BIRTH = null,
                BIO = "My Name is Theon Greyjoy. I'm member of House Greyjoy";

            var USER_ACCOUNT_API_URL = '/api/user/v0/accounts/user';

            var createMockUserAccountModel = function (data) {
                data = {
                    username: data.username || USERNAME,
                    name: data.name || FULLNAME,
                    email: data.email || EMAIL,
                    password: data.password || '',
                    language: _.isUndefined(data.language) ? LANGUAGE[0][0] : data.language,
                    country: data.country || COUNTRY,
                    date_joined: data.date_joined || DATE_JOINED,
                    gender: data.gender || GENDER,
                    goals: data.goals || GOALS,
                    level_of_education: data.level_of_education || LEVEL_OF_EDUCATION,
                    mailing_address: data.mailing_address || MAILING_ADDRESS,
                    year_of_birth: data.year_of_birth || YEAR_OF_BIRTH,
                    bio: data.bio || BIO
                };
                var model = new UserAccountModel(data);
                model.url = USER_ACCOUNT_API_URL;
                return model;
            };

            var createFieldData = function (fieldType, fieldData) {
                var data = {
                    model: fieldData.model || createMockUserAccountModel({}),
                    title: fieldData.title || 'Field Title',
                    valueAttribute: fieldData.valueAttribute,
                    helpMessage: fieldData.helpMessage || 'I am a field message',
                    placeholderValue: fieldData.placeholderValue || 'I am a placeholder message'
                };

                switch (fieldType) {
                    case FieldViews.DropdownFieldView:
                        data['required'] = fieldData.required || false;
                        data['options'] = fieldData.options || [['1', 'Option1'], ['2', 'Option2'], ['3', 'Option3']];
                        break;
                    case FieldViews.LinkFieldView:
                    case FieldViews.PasswordFieldView:
                        data['linkTitle'] = fieldData.linkTitle || "Link Title";
                        data['linkHref'] = fieldData.linkHref || "/path/to/resource";
                        data['emailAttribute'] = 'email';
                        break;
                }

                return data;
            };

            var createErrorMessage = function(attribute, user_message) {
                var field_errors = {}
                field_errors[attribute] = {
                    "user_message": user_message
                }
                return {
                    "field_errors": field_errors
                }
            };

            var expectTitleAndMessageToBe = function(view, expectedTitle, expectedMessage) {
                expect(view.$('.u-field-title').text().trim()).toBe(expectedTitle);
                expect(view.$('.u-field-message').text().trim()).toBe(expectedMessage);
            };

            var expectMessageContains = function(view, expectedText) {
                expect(view.$('.u-field-message').html()).toContain(expectedText);
            };

            var expectAjaxRequestWithData = function(data) {
                AjaxHelpers.expectJsonRequest(
                    requests, 'PATCH', USER_ACCOUNT_API_URL, data
                );
            };

            beforeEach(function () {
                TemplateHelpers.installTemplate('templates/fields/field_readonly');
                TemplateHelpers.installTemplate('templates/fields/field_dropdown');
                TemplateHelpers.installTemplate('templates/fields/field_link');
                TemplateHelpers.installTemplate('templates/fields/field_text');
                TemplateHelpers.installTemplate('templates/fields/field_textarea');

                timerCallback = jasmine.createSpy('timerCallback');
                jasmine.Clock.useMock();
            });

            it("updates messages correctly for all fields", function() {
                for (var i=0; i<fieldViewClasses.length; i++) {
                    var fieldViewClass = fieldViewClasses[i];
                    var fieldData = createFieldData(fieldViewClass, {
                        title: 'Username',
                        valueAttribute: 'username',
                        helpMessage: 'The username that you use to sign in to edX.'
                    });

                    var view = new fieldViewClass(fieldData).render();

                    var message = "This is field no." + i + "." ;
                    view.message(message);
                    expectMessageContains(view, message);

                    view.showHelpMessage();
                    expectMessageContains(view, view.helpMessage);

                    view.showInProgressMessage();
                    expectMessageContains(view, view.indicators['inProgress']);
                    expectMessageContains(view, view.messages['inProgress']);

                    if (view.fieldType === 'textarea') {
                        expect(view.$('textarea').length).toBe(1);
                        expect(view.el).toHaveClass("mode-edit");

                        view.showSuccessMessage();

                        expect(view.el).not.toHaveClass("mode-edit");
                        expect(view.$('textarea').length).toBe(0);
                    }
                    else {
                        view.showSuccessMessage();
                        expectMessageContains(view, view.indicators['success']);
                        expectMessageContains(view, view.getMessage('success'));
                    }

                    expect(timerCallback).not.toHaveBeenCalled();

                    view.showErrorMessage({
                        responseText: JSON.stringify(createErrorMessage(fieldData.valueAttribute, 'Please fix this.')),
                        status: 400
                    });
                    expectMessageContains(view, view.indicators['validationError']);

                    view.showErrorMessage({status: 500});
                    expectMessageContains(view, view.indicators['error']);
                    expectMessageContains(view, view.indicators['error']);
                }
            });

            it("resets to help message some time after success message is set", function() {
                var updatedFielViewClasses = fieldViewClasses;
                updatedFielViewClasses.pop();

                for (var i=0; i<updatedFielViewClasses.length; i++) {
                    var fieldViewClass = updatedFielViewClasses[i];
                    var fieldData = createFieldData(fieldViewClass, {
                        title: 'Username',
                        valueAttribute: 'username',
                        helpMessage: 'The username that you use to sign in to edX.'
                    });

                    var view = new fieldViewClass(fieldData).render();

                    view.showHelpMessage();
                    expectMessageContains(view, view.helpMessage);
                    view.showSuccessMessage();
                    if (view)
                    expectMessageContains(view, view.indicators['success']);
                    jasmine.Clock.tick(5000);
                    // Message gets reset
                    expectMessageContains(view, view.helpMessage);

                    view.showSuccessMessage();
                    expectMessageContains(view, view.indicators['success']);
                    // But if we change the message, it should not get reset.
                    view.message("Do not reset this!");
                    jasmine.Clock.tick(5000);
                    expectMessageContains(view, "Do not reset this!");
                }
            });

            it("sends a PATCH request when saveAttributes is called", function() {

                requests = AjaxHelpers.requests(this);

                var fieldViewClass = FieldViews.EditableFieldView;
                var fieldData = createFieldData(fieldViewClass, {
                    title: 'Preferred Language',
                    valueAttribute: 'language',
                    helpMessage: 'Your preferred language.'
                })

                var view = new fieldViewClass(fieldData);
                view.saveAttributes(
                    {'language': 'ur'},
                    {'headers': {'Priority': 'Urgent'}}
                );

                var request = requests[0];
                expect(request.method).toBe('PATCH');
                expect(request.requestHeaders['Content-Type']).toBe('application/merge-patch+json;charset=utf-8');
                expect(request.requestHeaders['Priority']).toBe('Urgent');
                expect(request.requestBody).toBe('{"language":"ur"}');
            });

            it("correctly renders ReadonlyFieldView", function() {
                var fieldData = createFieldData(FieldViews.ReadonlyFieldView, {
                    title: 'Username',
                    valueAttribute: 'username',
                    helpMessage: 'The username that you use to sign in to edX.'
                });
                var view = new FieldViews.ReadonlyFieldView(fieldData).render();

                expectTitleAndMessageToBe(view, fieldData.title, fieldData.helpMessage);
                expect(view.$('.u-field-value input').val().trim()).toBe(USERNAME);
            });

            it("correctly updates ReadonlyFieldView on model update", function() {
                var fieldData = createFieldData(FieldViews.ReadonlyFieldView, {
                    title: 'Username',
                    valueAttribute: 'username',
                    helpMessage: 'The username that you use to sign in to edX.'
                });
                var view = new FieldViews.ReadonlyFieldView(fieldData).render();

                expect(view.$('.u-field-value input').val().trim()).toBe(USERNAME);
                view.model.set({'username': 'bookworm'});
                expect(view.$('.u-field-value input').val().trim()).toBe('bookworm');
            });

            it("correctly renders TextFieldView", function() {
                var fieldData = createFieldData(FieldViews.TextFieldView, {
                    title: 'Full Name',
                    valueAttribute: 'name',
                    helpMessage: 'This is the name used on your edX certificates. Changes to this field are reviewed.'
                });
                var view = new FieldViews.TextFieldView(fieldData).render();

                expectTitleAndMessageToBe(view, fieldData.title, fieldData.helpMessage);
                expect(view.$('.u-field-value > input').val()).toBe(FULLNAME);
            });

            it("correctly persists changes to TextFieldView, EmailFieldView & DropdownFieldView", function() {

                requests = AjaxHelpers.requests(this);

                var validationError = "Your name must contain more than three characters.";

                var fieldViewClasses = [
                    [FieldViews.TextFieldView, '.u-field-value > input', 'Next'],
                    [FieldViews.EmailFieldView, '.u-field-value > input', 'Next'],
                    [FieldViews.DropdownFieldView, '.u-field-value > select', '1']
                ];

                for (var i=0; i<fieldViewClasses.length; i++) {

                    var fieldViewClass = fieldViewClasses[i][0];
                    var fieldData = createFieldData(fieldViewClass, {
                        title: 'Full Name',
                        valueAttribute: 'name',
                        helpMessage: 'edX full name'
                    });

                    var selector = fieldViewClasses[i][1];
                    var data = {'name': fieldViewClasses[i][2]};

                    var view = new fieldViewClasses[i][0](fieldData).render();

                    // Initially the help message is shown
                    expectMessageContains(view, fieldData.helpMessage);

                    view.$(selector).val(data.name).change();
                    // When the value in the field is changed
                    expect(view.fieldValue()).toBe(fieldViewClasses[i][2]);
                    expectMessageContains(view, view.indicators['inProgress']);
                    expectMessageContains(view, view.messages['inProgress']);
                    expectAjaxRequestWithData(data);

                    AjaxHelpers.respondWithNoContent(requests);
                    // When server returns success.
                    expectMessageContains(view, view.indicators['success']);

                    view.$(selector).val(data.name + 'with error').change();
                    AjaxHelpers.respondWithError(requests, 500);
                    // When server returns a 500 error
                    expectMessageContains(view, view.indicators['error']);
                    expectMessageContains(view, view.messages['error']);

                    view.$(selector).val('').change();
                    AjaxHelpers.respondWithError(requests, 400, createErrorMessage(fieldData.valueAttribute, validationError));
                    // When server returns a validation error
                    expectMessageContains(view, view.indicators['validationError']);
                    expectMessageContains(view, validationError);
                }
            });

            it("correctly renders LinkFieldView", function() {
                var fieldData = createFieldData(FieldViews.LinkFieldView, {
                    title: 'Title',
                    linkTitle: 'Link title',
                    helpMessage: 'Click the link.'
                });
                var view = new FieldViews.LinkFieldView(fieldData).render();
                expectTitleAndMessageToBe(view, fieldData.title, fieldData.helpMessage);
                expect(view.$('.u-field-value > a').text().trim()).toBe(fieldData.linkTitle);
            });

            it("sends request to reset password on clicking link in PasswordFieldView", function() {
                requests = AjaxHelpers.requests(this);

                var fieldData = createFieldData(FieldViews.PasswordFieldView, {
                    linkHref: '/password_reset'
                });

                var view = new FieldViews.PasswordFieldView(fieldData).render();
                view.$('.u-field-value > a').click();
                AjaxHelpers.expectRequest(requests, 'POST', '/password_reset', "email=legolas%40woodland.middlearth");
                AjaxHelpers.respondWithJson(requests, {"success": "true"})
                expectMessageContains(view,
                    "We've sent a message to legolas@woodland.middlearth. Click the link in the message to reset your password."
                );
            });

            it("correctly renders TextAreaFieldView with edit mode", function() {
                var fieldData = createFieldData(FieldViews.TextareaFieldView, {
                    title: 'About me',
                    valueAttribute: 'bio',
                    helpMessage: 'Wicked is good'
                });
                var view = new FieldViews.TextareaFieldView(fieldData).render();

                expectTitleAndMessageToBe(view, fieldData.title, fieldData.helpMessage);
                expect(view.$('.u-field-value > textarea').val()).toBe(BIO);
            });

            it("correctly renders TextAreaFieldView with display mode", function() {
                var fieldData = createFieldData(FieldViews.TextareaFieldView, {
                    title: 'About me',
                    valueAttribute: 'bio',
                    helpMessage: 'Wicked is good',
                    placeholderValue: "Tell other edX learners a little about yourself: where you live, what your interests are, why you’re taking courses on edX, or what you hope to learn."
                });
                // set bio to empty to see the placeholder.
                fieldData.model.set({bio: ''});
                var fieldObject = new FieldViews.TextareaFieldView(fieldData);
                fieldObject.showDisplayMode();

                var view = fieldObject.render();
                // for placeholder we add '+' in start of message.
                expectTitleAndMessageToBe(view, '+ ' + fieldData.title, fieldData.helpMessage);
                expect(view.$('.u-field-value').text()).toBe(fieldData.placeholderValue);
            });

        });
    });
