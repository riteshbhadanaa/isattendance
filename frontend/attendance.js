document.getElementById('markAttendance').addEventListener('click', function() {
    const token = localStorage.getItem('token');
    const userId = localStorage.getItem('userId');
    if (!token || !userId) {
        alert('User not authenticated. Please log in.');
        return;
    }

    fetch('https://ritesh-peach.vercel.app/api/attendance', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ userId })
    })
    .then(response => {
        if (response.ok) {
            alert('Attendance marked successfully');
        } else {
            alert('Attendance already marked for today');
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

// View Records
document.getElementById('viewRecords').addEventListener('click', function() {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('User not authenticated. Please log in.');
        return;
    }

    fetch('http://localhost:3000/api/records', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => response.json())
    .then(data => {
        const recordsTableBody = document.getElementById('recordsTableBody');
        recordsTableBody.innerHTML = '';
        data.forEach(record => {
            const recordRow = document.createElement('tr');
            recordRow.innerHTML = `
                <td>${record.firstName} ${record.lastName}</td>
                <td>${new Date(record.timestamp).toLocaleString()}</td>
                <td>${record.emailOrMobile}</td>
                <td>
                    <span class="icon" onclick="editRecord('${record.userId}')">&#9998;</span>
                    <span class="icon" onclick="deleteRecord('${record.userId}')">&#10060;</span>
                </td>
            `;
            recordsTableBody.appendChild(recordRow);
        });
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

// Edit Record
function editRecord(userId) {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('User not authenticated. Please log in.');
        return;
    }

    fetch(`https://ritesh-peach.vercel.app/api/records/${userId}`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => response.json())
    .then(record => {
        if (record && record._id) {
            // Populate the form with the current record details
            document.getElementById('editUserId').value = record._id;
            document.getElementById('editFirstName').value = record.firstName;
            document.getElementById('editLastName').value = record.lastName;
            document.getElementById('editEmailOrMobile').value = record.emailOrMobile;

            // Display the modal
            document.getElementById('editModal').style.display = 'flex';
        } else {
            alert('Error: Record not found');
        }
    })
    .catch(error => {
        console.error('Error fetching record:', error);
    });
}

// Save Changes
document.getElementById('editForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const token = localStorage.getItem('token');
    if (!token) {
        alert('User not authenticated. Please log in.');
        return;
    }

    const userId = document.getElementById('editUserId').value;
    const updatedData = {
        firstName: document.getElementById('editFirstName').value,
        lastName: document.getElementById('editLastName').value,
        emailOrMobile: document.getElementById('editEmailOrMobile').value
    };

    fetch(`https://ritesh-peach.vercel.app/api/records/${userId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(updatedData)
    })
    .then(response => {
        if (response.ok) {
            alert('Record updated successfully');
            document.getElementById('editModal').style.display = 'none';
            document.getElementById('viewRecords').click(); // Refresh records
        } else {
            alert('Failed to update record');
        }
    })
    .catch(error => {
        console.error('Error updating record:', error);
    });
});

// Close Modal
document.getElementById('closeModal').addEventListener('click', function() {
    document.getElementById('editModal').style.display = 'none';
});

// Delete Record
function deleteRecord(userId) {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('User not authenticated. Please log in.');
        return;
    }

    if (confirm('Are you sure you want to delete this record?')) {
        fetch(`https://ritesh-peach.vercel.app/api/records/${userId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(response => {
            if (response.ok) {
                alert('Record deleted successfully');
                document.getElementById('viewRecords').click(); // Refresh records
            } else {
                alert('Failed to delete record');
            }
        })
        .catch(error => {
            console.error('Error deleting record:', error);
        });
    }
}