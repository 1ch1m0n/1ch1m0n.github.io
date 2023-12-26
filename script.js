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

        // Create additional buttons when a category button is clicked
        for (let i = 1; i <= 3; i++) {
            var additionalButton = document.createElement('button');
            additionalButton.innerText = 'Subcategory ' + i;
            additionalButton.onclick = (function (index) {
                return function() {
                    expandContainer('Subcategory ' + index);
                };
            })(i);
            categoriesContainer.appendChild(additionalButton);
        }
    }

    // Show the categories
    categoriesContainer.style.display = 'block';
}

// Function to expand the container based on the subcategory
function expandContainer(subcategory) {
    // Example: Add logic to expand the container based on the subcategory clicked
    alert('Expanded Container for ' + subcategory);
}
