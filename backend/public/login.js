// Ensure the Google Sign-In script is loaded before executing this code
document.addEventListener('DOMContentLoaded', (event) => {
    // Define the onSignIn function which will be called after a successful Google Sign-In
    window.onSignIn = function(googleUser) {
        // Get the Google ID token
        const id_token = googleUser.getAuthResponse().id_token;

        // Send the ID token to your server for verification and login
        fetch('http://localhost:3000/api/google-login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token: id_token })
        })
        .then(response => response.json())
        .then(data => {
            // Handle the response from the server (e.g., save the token, redirect)
            if (data.token) {
                // Store the JWT token in local storage or cookies
                localStorage.setItem('token', data.token);

                // Redirect to a protected page or dashboard
                window.location.href = '/success';
            } else {
                // Handle errors (e.g., display an error message)
                console.error('Login failed:', data.error);
            }
        })
        .catch(error => {
            // Handle network errors
            console.error('Network error:', error);
        });
    };
});
