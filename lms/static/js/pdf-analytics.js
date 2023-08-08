// eslint-disable-next-line camelcase
function sendLog(name, data, event_type) {
    // eslint-disable-next-line no-var
    var message = data || {};
    // eslint-disable-next-line no-undef
    message.chapter = PDF_URL || '';
    message.name = 'textbook.pdf.' + name;
    /* eslint-disable-next-line camelcase, no-undef */
    Logger.log(event_type || message.name, message);
}

// this event is loaded after the others to accurately represent the order of events:
// click next -> pagechange
$(function() {
    /* eslint-disable-next-line camelcase, no-var */
    var first_page = true;
    // eslint-disable-next-line no-var
    var scroll = {timeStamp: 0, direction: null};

    $(window).bind('pagechange', function(event) {
    // log every page render
        /* eslint-disable-next-line no-undef, no-var */
        var page = PDFViewerApplication.page;
        /* eslint-disable-next-line camelcase, no-var */
        var old_page = event.originalEvent.previousPageNumber;
        // pagechange is called many times per viewing.
        // eslint-disable-next-line camelcase
        if (old_page !== page || first_page) {
            // eslint-disable-next-line camelcase
            first_page = false;
            if ((event.timeStamp - scroll.timeStamp) < 50) {
                sendLog('page.scrolled', {page: page, direction: scroll.direction});
            }
            // eslint-disable-next-line camelcase
            sendLog('page.loaded', {type: 'gotopage', old: old_page, new: page}, 'book');
            scroll.timeStamp = 0;
        }
    });

    $('#viewerContainer').bind('DOMMouseScroll mousewheel', function(event) {
        scroll.timeStamp = event.timeStamp;
        // eslint-disable-next-line no-undef
        scroll.direction = PDFViewerApplication.pdfViewer.scroll.down ? 'down' : 'up';
    });
});

$('#viewThumbnail,#sidebarToggle').on('click', function() {
    // eslint-disable-next-line no-undef
    sendLog('thumbnails.toggled', {page: PDFViewerApplication.page});
});

$('#thumbnailView a').live('click', function() {
    sendLog('thumbnail.navigated', {page: $('#thumbnailView a').index(this) + 1, thumbnail_title: $(this).attr('title')});
});

$('#viewOutline').on('click', function() {
    // eslint-disable-next-line no-undef
    sendLog('outline.toggled', {page: PDFViewerApplication.page});
});

$('#previous').on('click', function() {
    // eslint-disable-next-line no-undef
    sendLog('page.navigatednext', {type: 'prevpage', new: PDFViewerApplication.page - 1}, 'book');
});

$('#next').on('click', function() {
    // eslint-disable-next-line no-undef
    sendLog('page.navigatednext', {type: 'nextpage', new: PDFViewerApplication.page + 1}, 'book');
});

$('#zoomIn,#zoomOut').on('click', function() {
    /* eslint-disable-next-line eqeqeq, no-undef */
    sendLog('zoom.buttons.changed', {direction: $(this).attr('id') == 'zoomIn' ? 'in' : 'out', page: PDFViewerApplication.page});
});

$('#pageNumber').on('change', function() {
    sendLog('page.navigated', {page: $(this).val()});
});

/* eslint-disable-next-line camelcase, no-var */
var old_amount = 1;
$(window).bind('scalechange', function(event) {
    // eslint-disable-next-line no-var
    var amount = event.originalEvent.scale;
    // eslint-disable-next-line camelcase
    if (amount !== old_amount) {
        // eslint-disable-next-line no-undef
        sendLog('display.scaled', {amount: amount, page: PDFViewerApplication.page});
        // eslint-disable-next-line camelcase
        old_amount = amount;
    }
});

$('#scaleSelect').on('change', function() {
    // eslint-disable-next-line no-undef
    sendLog('zoom.menu.changed', {amount: $('#scaleSelect').val(), page: PDFViewerApplication.page});
});

/* eslint-disable-next-line camelcase, no-var */
var search_event = null;
$(window).bind('find findhighlightallchange findagain findcasesensitivitychange', function(event) {
    /* eslint-disable-next-line camelcase, eqeqeq */
    if (search_event && event.type == 'find') {
        clearTimeout(search_event);
    }
    // eslint-disable-next-line camelcase
    search_event = setTimeout(function() {
        // eslint-disable-next-line no-var
        var message = event.originalEvent.detail;
        message.status = $('#findMsg').text();
        // eslint-disable-next-line no-undef
        message.page = PDFViewerApplication.page;
        /* eslint-disable-next-line camelcase, no-var */
        var event_name = 'search';
        // eslint-disable-next-line default-case
        switch (event.type) {
        case 'find':
            // eslint-disable-next-line camelcase
            event_name += '.executed';
            break;
        case 'findhighlightallchange':
            // eslint-disable-next-line camelcase
            event_name += '.highlight.toggled';
            break;
        case 'findagain':
            // eslint-disable-next-line camelcase
            event_name += '.navigatednext';
            break;
        case 'findcasesensitivitychange':
            // eslint-disable-next-line camelcase
            event_name += 'casesensitivity.toggled';
            break;
        }
        sendLog(event_name, message);
    }, 500);
});
