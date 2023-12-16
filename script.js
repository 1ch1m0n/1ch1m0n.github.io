function showContent(contentId) {
    hideAllContent();
    var content = document.getElementById(contentId);
    content.style.maxHeight = content.scrollHeight + "px";

    // Additional logic to handle specific cases
    if (contentId === 'ctf') {
        showCTFContent('ctf1');
    }
}

function showCTFContent(ctfId) {
    var ctfContent = document.getElementById(ctfId);
    if (ctfContent) {
        ctfContent.style.maxHeight = ctfContent.scrollHeight + "px";
    }
}

function hideAllContent() {
    var contents = document.getElementsByClassName('content');
    for (var i = 0; i < contents.length; i++) {
        contents[i].style.maxHeight = '0';
    }
}
