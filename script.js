function showContent(contentId) {
    hideAllContent();
    var content = document.getElementById(contentId);
    content.style.maxHeight = content.scrollHeight + "px";

    // Additional logic to handle specific cases
    if (contentId === 'ctf') {
        showContent('ctf1');
    } else if (contentId === 'ctf1') { // Fix the typo here
        // Handle 'ctf1' case if needed
    } else if (contentId === 'ctf2') {
        // Handle 'ctf2' case if needed
    }
}

function hideAllContent() {
    var contents = document.getElementsByClassName('content');
    for (var i = 0; i < contents.length; i++) {
        contents[i].style.maxHeight = '0';
    }
}
