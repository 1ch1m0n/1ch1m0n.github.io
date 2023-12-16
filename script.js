function showContent(contentId) {
    hideAllContent();
    var content = document.getElementById(contentId);
    content.style.maxHeight = content.scrollHeight + "px";

     // Additional logic to handle specific cases
     if (contentId === 'school1') {
        showContent('ctf1');
    } else if (contentId === 'school2') {
        showContent('ctf2');
    }
}

function hideAllContent() {
    var contents = document.getElementsByClassName('content');
    for (var i = 0; i < contents.length; i++) {
        contents[i].style.maxHeight = '0';
    }
}