if Backbone?
  class @DiscussionContentView extends Backbone.View


    events:
      "click .discussion-flag-abuse": "toggleFlagAbuse"
      "keydown .discussion-flag-abuse":
        (event) -> DiscussionUtil.activateOnSpace(event, @toggleFlagAbuse)

    attrRenderer:
      ability: (ability) ->
        for action, selector of @abilityRenderer
          if not ability[action]
            selector.disable.apply(@)
          else
            selector.enable.apply(@)

    abilityRenderer:
      editable:
        enable: -> @$(".action-edit").closest("li").show()
        disable: -> @$(".action-edit").closest("li").hide()
      can_delete:
        enable: -> @$(".action-delete").closest("li").show()
        disable: -> @$(".action-delete").closest("li").hide()

      can_openclose:
        enable: ->
          _.each(
            [".action-close", ".action-pin"],
            (selector) => @$(selector).closest("li").show()
          )
        disable: ->
          _.each(
            [".action-close", ".action-pin"],
            (selector) => @$(selector).closest("li").hide()
          )

    renderPartialAttrs: ->
      for attr, value of @model.changedAttributes()
        if @attrRenderer[attr]
          @attrRenderer[attr].apply(@, [value])

    renderAttrs: ->
      for attr, value of @model.attributes
        if @attrRenderer[attr]
          @attrRenderer[attr].apply(@, [value])

    makeWmdEditor: (cls_identifier) =>
      if not @$el.find(".wmd-panel").length
        DiscussionUtil.makeWmdEditor @$el, $.proxy(@$, @), cls_identifier

    getWmdEditor: (cls_identifier) =>
      DiscussionUtil.getWmdEditor @$el, $.proxy(@$, @), cls_identifier

    getWmdContent: (cls_identifier) =>
      DiscussionUtil.getWmdContent @$el, $.proxy(@$, @), cls_identifier

    setWmdContent: (cls_identifier, text) =>
      DiscussionUtil.setWmdContent @$el, $.proxy(@$, @), cls_identifier, text


    initialize: ->
      @model.bind('change', @renderPartialAttrs, @)
      @listenTo(@model, "change:endorsed", =>
        if @model instanceof Comment
          @trigger("comment:endorse")
      )

  class @DiscussionContentShowView extends DiscussionContentView
    events:
      "click .action-follow": "toggleFollow"
      "click .action-answer": "toggleEndorse"
      "click .action-endorse": "toggleEndorse"
      "click .action-vote": "toggleVote"
      "click .action-more": "showSecondaryActions"
      "click .action-pin": "togglePin"
      "click .action-edit": "edit"
      "click .action-delete": "_delete"
      "click .action-report": "toggleReport"
      "click .action-close": "toggleClose"

    updateButtonState: (selector, checked) =>
      $button = @$(selector)
      $button.toggleClass("is-checked", checked)
      $button.attr("aria-checked", checked)

    attrRenderer: $.extend({}, DiscussionContentView.prototype.attrRenderer, {
      subscribed: (subscribed) ->
        @updateButtonState(".action-follow", subscribed)

      endorsed: (endorsed) ->
        selector = if @model.get("thread").get("thread_type") == "question" then ".action-answer" else ".action-endorse"
        @updateButtonState(selector, endorsed)
        $button = @$(selector)
        $button.toggleClass("is-clickable", @model.canBeEndorsed())
        $button.toggleClass("is-checked", endorsed)
        if endorsed || @model.canBeEndorsed()
          $button.removeAttr("hidden")
        else
          $button.attr("hidden", "hidden")

      votes: (votes) ->
        selector = ".action-vote"
        @updateButtonState(selector, window.user.voted(@model))
        button = @$el.find(selector)
        numVotes = votes.up_count
        button.find(".js-sr-vote-count").html(
          interpolate(gettext("currently %(numVotes)s votes"), {numVotes: numVotes}, true)
        )
        button.find(".js-visual-vote-count").html("" + numVotes)

      pinned: (pinned) ->
        @updateButtonState(".action-pin", pinned)
        @$(".post-label-pinned").toggle(pinned)

      abuse_flaggers: (abuse_flaggers) ->
        flagged = (
          window.user.id in abuse_flaggers or
          (DiscussionUtil.isFlagModerator and abuse_flaggers.length > 0)
        )
        @updateButtonState(".action-report", flagged)
        @$(".post-label-reported").toggle(flagged)

      closed: (closed) ->
        @updateButtonState(".action-close", closed)
        @$(".post-label-closed").toggle(closed)
    })

    showSecondaryActions: (event) =>
      event.preventDefault()
      event.stopPropagation()
      @$(".action-more").addClass("is-expanded")
      @$(".actions-dropdown").addClass("is-expanded")
      $("body").on("click", @hideSecondaryActions)

    hideSecondaryActions: (event) =>
      event.preventDefault()
      event.stopPropagation()
      @$(".action-more").removeClass("is-expanded")
      @$(".actions-dropdown").removeClass("is-expanded")
      $("body").off("click", @hideSecondaryActions)

    toggleFollow: (event) =>
      event.preventDefault()
      is_subscribing = not @model.get("subscribed")
      url = @model.urlFor(if is_subscribing then "follow" else "unfollow")
      if is_subscribing
        msg = gettext("We had some trouble subscribing you to this thread. Please try again.")
      else
        msg = gettext("We had some trouble unsubscribing you from this thread. Please try again.")
      DiscussionUtil.updateWithUndo(
        @model,
        {"subscribed": is_subscribing},
        {url: url, type: "POST", $elem: $(event.currentTarget)},
        msg
      )

    toggleEndorse: (event) =>
      event.preventDefault()
      if not @model.canBeEndorsed()
        return
      is_endorsing = not @model.get("endorsed")
      url = @model.urlFor("endorse")
      updates =
        endorsed: is_endorsing
        endorsement: if is_endorsing then {username: DiscussionUtil.getUser().get("username"), time: new Date().toISOString()} else null
      if @model.get('thread').get('thread_type') == 'question'
        if is_endorsing
          msg = gettext("We had some trouble marking this response as an answer.  Please try again.")
        else
          msg = gettext("We had some trouble removing this response as an answer.  Please try again.")
      else
        if is_endorsing
          msg = gettext("We had some trouble marking this response endorsed.  Please try again.")
        else
          msg = gettext("We had some trouble removing this endorsement.  Please try again.")
      beforeFunc = () => @model.trigger("comment:endorse")
      DiscussionUtil.updateWithUndo(
        @model,
        updates,
        {url: url, type: "POST", data: {endorsed: is_endorsing}, beforeSend: beforeFunc, $elem: $(event.currentTarget)},
        msg
      ).always(@trigger("comment:endorse")) # ensures UI components get updated to the correct state when ajax completes

    toggleVote: (event) =>
      event.preventDefault()
      user = DiscussionUtil.getUser()
      is_voting = not user.voted(@model)
      url = @model.urlFor(if is_voting then "upvote" else "unvote")
      updates =
        upvoted_ids: (if is_voting then _.union else _.difference)(user.get('upvoted_ids'), [@model.id])
      DiscussionUtil.updateWithUndo(
        user,
        updates,
        {url: url, type: "POST", $elem: $(event.currentTarget)},
        gettext("We had some trouble saving your vote.  Please try again.")
      ).done(() => if is_voting then @model.vote() else @model.unvote())

    togglePin: (event) =>
      event.preventDefault()
      is_pinning = not @model.get("pinned")
      url = @model.urlFor(if is_pinning then "pinThread" else "unPinThread")
      if is_pinning
        msg = gettext("We had some trouble pinning this thread. Please try again.")
      else
        msg = gettext("We had some trouble unpinning this thread. Please try again.")
      DiscussionUtil.updateWithUndo(
        @model,
        {pinned: is_pinning},
        {url: url, type: "POST", $elem: $(event.currentTarget)},
        msg
      )

    toggleReport: (event) =>
      event.preventDefault()
      user = DiscussionUtil.getUser()
      if user.id in @model.get("abuse_flaggers") or (DiscussionUtil.isFlagModerator and @model.get("abuse_flaggers").length > 0)
        is_flagging = false
        msg = gettext("We had some trouble removing your flag on this post.  Please try again.")
      else
        is_flagging = true
        msg = gettext("We had some trouble reporting this post.  Please try again.")
      url = @model.urlFor(if is_flagging then "flagAbuse" else "unFlagAbuse")
      updates =
        abuse_flaggers: (if is_flagging then _.union else _.difference)(@model.get("abuse_flaggers"), [user.id])
      DiscussionUtil.updateWithUndo(
        @model,
        updates,
        {url: url, type: "POST", $elem: $(event.currentTarget)},
        msg
      )

    toggleClose: (event) =>
      event.preventDefault()
      is_closing = not model.get('closed')
      if is_closing
        msg = gettext("We had some trouble closing this thread.  Please try again.")
      else
        msg = gettext("We had some trouble reopening this thread.  Please try again.")
      updates = {closed: is_closing}
      DiscussionUtil.updateWithUndo(
        @model,
        updates,
        {url: @model.urlFor("close"), type: "POST", data: updates, $elem: $(event.currentTarget)},
        msg
      )

    getAuthorDisplay: ->
      _.template($("#post-user-display-template").html())(
        username: @model.get('username') || null
        user_url: @model.get('user_url')
        is_community_ta: @model.get('community_ta_authored')
        is_staff: @model.get('staff_authored')
      )

    getEndorserDisplay: ->
      endorsement = @model.get('endorsement')
      if endorsement and endorsement.username
        _.template($("#post-user-display-template").html())(
          username: endorsement.username
          user_url: DiscussionUtil.urlFor('user_profile', endorsement.user_id)
          is_community_ta: DiscussionUtil.isTA(endorsement.user_id)
          is_staff: DiscussionUtil.isStaff(endorsement.user_id)
        )
