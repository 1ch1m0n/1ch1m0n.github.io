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

// Add functions for CTF 1 and CTF 2
function showContent(contentId) {
    hideAllContent();
    var content = document.getElementById(contentId);
    content.style.maxHeight = content.scrollHeight + "px";
}