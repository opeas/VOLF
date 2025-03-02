function copyToClipboard(event, link) {
    event.preventDefault(); // Prevents navigation to the page
    navigator.clipboard.writeText(link).then(function() {
        alert('The vulnerability link has been successfully copied.');
    }, function(err) {
        alert('Failed to copy the vulnerability link. Please contact the system administrator.');
        console.error('Failed to copy the vulnerability URL: ', err);
    });
}
