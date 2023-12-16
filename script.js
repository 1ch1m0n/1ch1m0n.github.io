function showContent(contentId) {
    hideAllContent();
    var content = document.getElementById(contentId);
    content.style.maxHeight = content.scrollHeight + "px";
}

function hideAllContent() {
    var contents = document.getElementsByClassName('content');
    for (var i = 0; i < contents.length; i++) {
        contents[i].style.maxHeight = '0';
    }
}

function showContent(sectionId) {
    var content = document.getElementById(sectionId);

    // Toggle the visibility of the content
    if (content.style.maxHeight) {
        content.style.maxHeight = null;
    } else {
        content.style.maxHeight = content.scrollHeight + "px";
    }

    // Prevent the default behavior of the click event
    event.preventDefault();
}