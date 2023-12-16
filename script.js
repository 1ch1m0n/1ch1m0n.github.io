// Add interactive features
function showCategories(competition) {
    var categoriesContainer = document.getElementById('categories');
    categoriesContainer.innerHTML = ''; // Clear previous content

    // Example categories, you can replace them with your own
    var categories = {
        'competition1': ['Forensics', 'Web', 'Pwn'],
        'competition2': ['Crypto', 'Reverse Engineering', 'Misc'],
    };

    if (categories[competition]) {
        categories[competition].forEach(function(category) {
            var categoryLink = document.createElement('a');
            categoryLink.href = '#'; // Add actual link or functionality
            categoryLink.innerText = category;
            categoriesContainer.appendChild(categoryLink);
        });
    }

    // Show the categories
    categoriesContainer.style.display = 'block';
}
