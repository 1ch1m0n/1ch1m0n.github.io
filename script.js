function showContent(contentId) {
    hideAllContent();
    var content = document.getElementById(contentId);
    content.style.maxHeight = content.scrollHeight + "px"; // Set max-height to the actual content height
}

function hideAllContent() {
    var contents = document.getElementsByClassName('content');
    for (var i = 0; i < contents.length; i++) {
        contents[i].style.maxHeight = '0';
    }
}
