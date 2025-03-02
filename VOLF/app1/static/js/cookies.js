function setCookie(name, value, days) {
    let expires = "";
    if (days) {
        let date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "") + expires + "; path=/";
    console.log(`Cookie set: ${name}=${value}`);
}

function getCookie(name) {
    let nameEQ = name + "=";
    let ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded and parsed');
    let themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        console.log('Theme toggle button found');
        themeToggle.addEventListener('click', function(event) {
            event.preventDefault(); // Prevents the default button behavior
            console.log('Theme toggle button clicked');
            let currentTheme = getCookie('theme') || 'dark';
            let newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            console.log(`Current theme: ${currentTheme}, New theme: ${newTheme}`);
            setCookie('theme', newTheme, 365); // Cookie valid for one year
            console.log(`New theme cookie value: ${getCookie('theme')}`); // Logs the new cookie value
            location.reload(); // Refresh the page to apply the new theme
        });
    } else {
        console.log('Theme toggle button not found');
    }
});
