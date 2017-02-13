define([
    'jquery', 'backbone', 'js/views/active_video_upload_list', 'js/collections/video',
    'js/views/previous_video_upload_list', 'js/views/active_video_upload'
], function($, Backbone, ActiveVideoUploadListView, VideoPagingCollection,
    PreviousVideoUploadListView, ActiveVideoUpload) {
    'use strict';
    var VideosIndexFactory = function(
        $contentWrapper,
        videoHandlerUrl,
        encodingsDownloadUrl,
        concurrentUploadLimit,
        uploadButton,
        previousUploads,
        videoSupportedFileFormats,
        videoUploadMaxFileSizeInGB
    ) {
        var activeView = new ActiveVideoUploadListView({
                postUrl: videoHandlerUrl,
                concurrentUploadLimit: concurrentUploadLimit,
                uploadButton: uploadButton,
                videoSupportedFileFormats: videoSupportedFileFormats,
                videoUploadMaxFileSizeInGB: videoUploadMaxFileSizeInGB,
                onFileUploadDone: function(activeVideos) {
                    $.ajax({
                        url: videoHandlerUrl,
                        contentType: 'application/json',
                        dataType: 'json',
                        type: 'GET'
                    }).done(function(responseData) {
                        var updatedCollection = new Backbone.Collection(responseData.videos).filter(function(video) {
                                // Include videos that are not in the active video upload list,
                                // or that are marked as Upload Complete
                                var isActive = activeVideos.where({videoId: video.get('edx_video_id')});
                                return isActive.length === 0 ||
                                       isActive[0].get('status') === ActiveVideoUpload.STATUS_COMPLETE;
                            }),
                            updatedView = new PreviousVideoUploadListView({
                                videoHandlerUrl: videoHandlerUrl,
                                collection: updatedCollection,
                                encodingsDownloadUrl: encodingsDownloadUrl
                            });
                        $contentWrapper.find('.wrapper-assets').replaceWith(updatedView.render().$el);
                    });
                }
            }),
            previousView = new PreviousVideoUploadListView({
                videoHandlerUrl: videoHandlerUrl,
                collection: new VideoPagingCollection(previousUploads["videos"], {
                    url: videoHandlerUrl,
                    first_page: previousUploads["start"],
                    last_page: previousUploads["end"],
                    page_size: previousUploads["page_size"],
                    sort_field: previousUploads["sort_field"],
                    total_count: previousUploads["total_count"],
                    sort_dir: previousUploads["sort_dir"]  
                }),
                encodingsDownloadUrl: encodingsDownloadUrl
            });
        $contentWrapper.append(activeView.render().$el);
        $contentWrapper.append(previousView.render().$el);
    };

    return VideosIndexFactory;
});
