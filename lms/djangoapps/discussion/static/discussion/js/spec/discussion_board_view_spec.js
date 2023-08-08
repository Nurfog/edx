// eslint-disable-next-line no-unused-vars
/* globals Discussion, DiscussionCourseSettings, DiscussionUser, DiscussionUtil */
(function(define) {
    'use strict';

    define(
        [
            'underscore',
            'jquery',
            'edx-ui-toolkit/js/utils/constants',
            'common/js/discussion/discussion',
            'common/js/spec_helpers/discussion_spec_helper',
            'discussion/js/views/discussion_board_view'
        ],
        function(_, $, constants, Discussion, DiscussionSpecHelper, DiscussionBoardView) {
            describe('DiscussionBoardView', function() {
                // eslint-disable-next-line no-var
                var createDiscussionBoardView;
                createDiscussionBoardView = function() {
                    // eslint-disable-next-line no-var
                    var discussionBoardView,
                        discussion = DiscussionSpecHelper.createTestDiscussion({}),
                        courseSettings = DiscussionSpecHelper.createTestCourseSettings();

                    setFixtures('<div class="discussion-board"><div class="forum-search"></div></div>');
                    DiscussionSpecHelper.setUnderscoreFixtures();

                    discussionBoardView = new DiscussionBoardView({
                        el: $('.discussion-board'),
                        discussion: discussion,
                        courseSettings: courseSettings
                    });
                    window.ENABLE_FORUM_DAILY_DIGEST = true;
                    window.user = new DiscussionUser({
                        id: 99
                    });

                    return discussionBoardView;
                };

                describe('goHome view', function() {
                    it('Ensure no ajax request when digests are unavailable', function() {
                        // eslint-disable-next-line no-var
                        var discussionBoardView = createDiscussionBoardView();
                        // eslint-disable-next-line no-undef
                        spyOn(DiscussionUtil, 'safeAjax').and.callThrough();
                        window.ENABLE_FORUM_DAILY_DIGEST = false;

                        discussionBoardView.goHome();
                        expect(DiscussionUtil.safeAjax).not.toHaveBeenCalled();
                    });
                    it('Verify the ajax request when digests are available', function() {
                        // eslint-disable-next-line no-var
                        var discussionBoardView = createDiscussionBoardView();
                        discussionBoardView.render();
                        // eslint-disable-next-line no-undef
                        spyOn(DiscussionUtil, 'safeAjax').and.callThrough();

                        discussionBoardView.goHome();
                        expect(DiscussionUtil.safeAjax).toHaveBeenCalled();
                    });
                });

                describe('Thread List View', function() {
                    it('should ensure the mode is all', function() {
                        // eslint-disable-next-line no-var
                        var discussionBoardView = createDiscussionBoardView().render(),
                            threadListView = discussionBoardView.discussionThreadListView;
                        expect(threadListView.mode).toBe('all');
                    });
                });

                describe('Search events', function() {
                    it('perform search when enter pressed inside search textfield', function() {
                        // eslint-disable-next-line no-var
                        var discussionBoardView = createDiscussionBoardView(),
                            threadListView;
                        discussionBoardView.render();
                        threadListView = discussionBoardView.discussionThreadListView;
                        // eslint-disable-next-line no-undef
                        spyOn(threadListView, 'performSearch');
                        discussionBoardView.$('.search-input').trigger($.Event('keydown', {
                            which: constants.keyCodes.enter
                        }));
                        expect(threadListView.performSearch).toHaveBeenCalled();
                    });

                    it('perform search when search icon is clicked', function() {
                        // eslint-disable-next-line no-var
                        var discussionBoardView = createDiscussionBoardView(),
                            threadListView;
                        discussionBoardView.render();
                        threadListView = discussionBoardView.discussionThreadListView;
                        // eslint-disable-next-line no-undef
                        spyOn(threadListView, 'performSearch');
                        discussionBoardView.$el.find('.search-button').click();
                        expect(threadListView.performSearch).toHaveBeenCalled();
                    });
                });
            });
        });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
