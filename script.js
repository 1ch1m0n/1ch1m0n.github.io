/*Hide Content */
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
    
     // Hide nested buttons when hiding all content
     var nestedButtons = document.querySelector('.nested-buttons');
     if (nestedButtons) {
         nestedButtons.style.maxHeight = '0';
}
