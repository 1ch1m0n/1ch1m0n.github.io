function hideAllContent() {
    var contents = document.getElementsByClassName('content');
    for (var i = 0; i < contents.length; i++) {
        contents[i].style.maxHeight = '0';
    }

    // Hide nested buttons when hiding all content
    var nestedButtons = document.getElementById('education');
    if (nestedButtons) {
        nestedButtons.style.maxHeight = '0';
    }
}
