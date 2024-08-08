document.getElementById('registerForm').addEventListener('submit', function(e) {
    e.preventDefault();
    let valid = true;

    // Clear previous error messages
    document.querySelectorAll('.error').forEach(error => error.textContent = '');

    // Validation logic
    const firstName = document.getElementById('firstName').value.trim();
    const lastName = document.getElementById('lastName').value.trim();
    const dob = document.getElementById('dob').value;
    const emailOrMobile = document.getElementById('emailOrMobile').value.trim();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const isStudent = document.getElementById('isStudent').checked;

    if (!firstName) {
        valid = false;
        document.getElementById('firstNameError').textContent = 'First name is required.';
    }

    if (!lastName) {
        valid = false;
        document.getElementById('lastNameError').textContent = 'Last name is required.';
    }

    if (!dob) {
        valid = false;
        document.getElementById('dobError').textContent = 'Date of birth is required.';
    }

    if (!emailOrMobile) {
        valid = false;
        document.getElementById('emailOrMobileError').textContent = 'Email or mobile number is required.';
    }

    if (!username) {
        valid = false;
        document.getElementById('usernameError').textContent = 'Username is required.';
    }

    if (password.length < 4) {
        valid = false;
        document.getElementById('passwordError').textContent = 'Password must be at least 6 characters.';
    }

    if (valid) {
        const role = isStudent ? 'user' : 'admin';

        // Submit the form data to the server
        const formData = {
            firstName,
            lastName,
            dob,
            contactMethod: document.querySelector('input[name="contactMethod"]:checked').value,
            emailOrMobile,
            gender: document.getElementById('gender').value,
            username,
            password,
            role
        };

        // Post data to server
        fetch('https://ritesh-peach.vercel.app/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                alert('Registration successful!');
                window.location.href = 'login.html';
            } else {
                alert('Registration failed. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
});
