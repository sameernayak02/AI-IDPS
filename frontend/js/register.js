document.addEventListener('DOMContentLoaded', () => {
    const registerForm    = document.getElementById('register-form');
    const registerError   = document.getElementById('register-error');
    const registerSuccess = document.getElementById('register-success');
    const registerBtn     = document.getElementById('register-btn');
    const roleNameSpan    = document.getElementById('role-name');

    const API_BASE = 'http://localhost:8000';

    // Get role from URL
    const urlParams = new URLSearchParams(window.location.search);
    let role = urlParams.get('role') || 'Analyst';
    
    // Capitalize first letter
    role = role.charAt(0).toUpperCase() + role.slice(1).toLowerCase();
    if (role !== 'Admin' && role !== 'Analyst') role = 'Analyst';

    roleNameSpan.textContent = role;

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        registerBtn.textContent = 'Creating Account…';
        registerBtn.disabled = true;
        registerError.classList.add('hidden');
        registerSuccess.classList.add('hidden');

        try {
            const res = await fetch(`${API_BASE}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, role })
            });

            const data = await res.json();

            if (!res.ok) {
                throw new Error(data.detail || 'Registration failed.');
            }

            registerSuccess.textContent = `Account created as ${role}! Redirecting to login...`;
            registerSuccess.classList.remove('hidden');
            
            setTimeout(() => {
                window.location.href = 'index.html';
            }, 2000);

        } catch (err) {
            registerError.textContent = err.message;
            registerError.classList.remove('hidden');
            registerBtn.textContent = 'Register Now →';
            registerBtn.disabled = false;
        }
    });
});
