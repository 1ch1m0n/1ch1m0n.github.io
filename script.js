// Add interactive features if needed
// Add interactive features if needed
document.getElementById('btnAnimate').addEventListener('click', function() {
    animateButton();
});

function animateButton() {
    var button = document.getElementById('btnAnimate');
    button.classList.add('animated');
    setTimeout(function() {
        button.classList.remove('animated');
    }, 1000);
}
