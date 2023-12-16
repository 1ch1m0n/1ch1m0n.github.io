function showContent(contentId) {
    hideAllContent();
    var content = document.getElementById(contentId);
    content.style.maxHeight = content.scrollHeight + "px";

     // Additional logic to handle specific cases
     if (contentId === 'ctf') {
        showContent('ctf1');
    } else if (contentId === 'ctf2') {
        showContent('ctf2');
    }
}

function hideAllContent() {
    var contents = document.getElementsByClassName('content');
    for (var i = 0; i < contents.length; i++) {
        contents[i].style.maxHeight = '0';
    }
}