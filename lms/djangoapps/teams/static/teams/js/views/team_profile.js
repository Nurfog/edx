/**
 * View for an individual team.
 */
(function(define) {
    'use strict';

    define([
        'backbone',
        'underscore',
        'gettext',
        'edx-ui-toolkit/js/utils/html-utils',
        'teams/js/views/team_discussion',
        'common/js/components/utils/view_utils',
        'teams/js/views/team_utils',
        'text!teams/templates/team-profile.underscore',
        'text!teams/templates/team-member.underscore',
        'text!teams/templates/team-assignment.underscore'
    ],
    function(Backbone, _, gettext, HtmlUtils, TeamDiscussionView, ViewUtils, TeamUtils,
        teamTemplate, teamMemberTemplate, teamAssignmentTemplate) {
        // eslint-disable-next-line no-var
        var TeamProfileView = Backbone.View.extend({

            errorMessage: gettext('An error occurred. Try again.'),

            events: {
                'click .leave-team-link': 'leaveTeam'
            },

            initialize: function(options) {
                this.teamEvents = options.teamEvents;
                this.context = options.context;
                this.setFocusToHeaderFunc = options.setFocusToHeaderFunc;

                this.countries = TeamUtils.selectorOptionsArrayToHashWithBlank(this.context.countries);
                this.languages = TeamUtils.selectorOptionsArrayToHashWithBlank(this.context.languages);
                this.topic = options.topic;

                this.listenTo(this.model, 'change', this.render);
            },

            render: function() {
                // eslint-disable-next-line no-var
                var memberships = this.model.get('membership'),
                    discussionTopicID = this.model.get('discussion_topic_id'),
                    isMember = TeamUtils.isUserMemberOfTeam(memberships, this.context.userInfo.username),
                    isAdminOrStaff = this.context.userInfo.privileged || this.context.userInfo.staff,
                    isInstructorManagedTopic = TeamUtils.isInstructorManagedTopic(this.topic.attributes.type),
                    maxTeamSize = this.topic.getMaxTeamSize(this.context.courseMaxTeamSize);

                // Assignments URL isn't provided if team assignments shouldn't be shown
                // so we can treat it like a toggle
                // eslint-disable-next-line no-var
                var showAssignments = !!this.context.teamsAssignmentsUrl;

                // eslint-disable-next-line no-var
                var showLeaveLink = isMember && (isAdminOrStaff || !isInstructorManagedTopic);

                HtmlUtils.setHtml(
                    this.$el,
                    HtmlUtils.template(teamTemplate)({
                        courseID: this.context.courseID,
                        discussionTopicID: discussionTopicID,
                        readOnly: !(this.context.userInfo.privileged || isMember),
                        country: this.countries[this.model.get('country')],
                        language: this.languages[this.model.get('language')],
                        membershipText: TeamUtils.teamCapacityText(memberships.length, maxTeamSize),
                        isMember: isMember,
                        isAdminOrStaff: isAdminOrStaff,
                        showLeaveLink: showLeaveLink,
                        showAssignments: showAssignments,
                        hasCapacity: maxTeamSize && (memberships.length < maxTeamSize),
                        hasMembers: memberships.length >= 1
                    })
                );
                this.discussionView = new TeamDiscussionView({
                    el: this.$('.discussion-module'),
                    readOnly: (!isMember && !isAdminOrStaff)
                });
                this.discussionView.render();

                if (showAssignments) {
                    this.getTeamAssignments();
                }

                this.renderTeamMembers();

                this.setFocusToHeaderFunc();
                return this;
            },

            getTeamAssignments: function() {
                // eslint-disable-next-line no-var
                var view = this;

                $.ajax({
                    type: 'GET',
                    url: view.context.teamsAssignmentsUrl.replace('team_id', view.model.get('id'))
                }).done(function(data) {
                    view.renderTeamAssignments(data);
                }).fail(function(data) {
                    TeamUtils.parseAndShowMessage(data, view.errorMessage);
                });
            },

            renderTeamAssignments: function(assignments) {
                // eslint-disable-next-line no-var
                var view = this;

                if (!assignments || !assignments.length) {
                    view.$('#assignments').text(gettext('No assignments for team'));
                    return;
                }

                _.each(assignments, function(assignment) {
                    HtmlUtils.append(
                        view.$('#assignments'),
                        HtmlUtils.template(teamAssignmentTemplate)({
                            displayName: assignment.display_name,
                            linkLocation: assignment.location
                        })
                    );
                });
            },

            renderTeamMembers: function() {
                // eslint-disable-next-line no-var
                var view = this;
                _.each(this.model.get('membership'), function(membership) {
                    HtmlUtils.append(
                        view.$('.members-info'),
                        HtmlUtils.template(teamMemberTemplate)({
                            imageUrl: membership.user.profile_image.image_url_medium,
                            username: membership.user.username,
                            memberProfileUrl: '/u/' + membership.user.username
                        })
                    );
                });
            },

            selectText: function(event) {
                event.preventDefault();
                $(event.currentTarget).select();
            },

            leaveTeam: function(event) {
                event.preventDefault();
                // eslint-disable-next-line no-var
                var view = this; // eslint-disable-line vars-on-top
                ViewUtils.confirmThenRunOperation(
                    gettext('Leave this team?'),
                    gettext("If you leave, you can no longer post in this team's discussions."
                            + 'Your place will be available to another learner.'),
                    gettext('Confirm'),
                    function() {
                        $.ajax({
                            type: 'DELETE',
                            url: view.context.teamMembershipDetailUrl.replace('team_id', view.model.get('id'))
                        }).done(function() {
                            view.model.fetch()
                                .done(function() {
                                    view.teamEvents.trigger('teams:update', {
                                        action: 'leave',
                                        team: view.model
                                    });
                                });
                        }).fail(function(data) {
                            TeamUtils.parseAndShowMessage(data, view.errorMessage);
                        });
                    }
                );
            }
        });

        return TeamProfileView;
    });
// eslint-disable-next-line no-undef
}).call(this, define || RequireJS.define);
