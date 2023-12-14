function showAboutMe() {
    hideAllContent();
    document.getElementById('aboutMe').style.display = 'block';
}

function showEducation() {
    hideAllContent();
    document.getElementById('education').style.display = 'block';
}

function showExperience() {
    hideAllContent();
    document.getElementById('experience').style.display = 'block';
}

function hideAllContent() {
    var contents = document.getElementsByClassName('content');
    for (var i = 0; i < contents.length; i++) {
        contents[i].style.display = 'none';
    }
}
