document.addEventListener('DOMContentLoaded', () => {
    const regForm     = document.getElementById('adminRegForm');
    const regError    = document.getElementById('reg-error');
    const regSuccess  = document.getElementById('reg-success');
    const submitBtn   = regForm.querySelector('.submit-btn');

    const API_BASE = 'http://localhost:8000';

    regForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Basic validation for password matching
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password').value;
        
        if (password !== confirmPassword) {
            regError.textContent = 'Passwords do not match!';
            regError.classList.remove('hidden');
            return;
        }

        submitBtn.textContent = 'Processing Registration…';
        submitBtn.disabled = true;
        regError.classList.add('hidden');
        regSuccess.classList.add('hidden');

        // Extract form data
        const formData = new FormData(regForm);
        const payload = {
            role: 'Admin',
            username: formData.get('userid'),
            password: password,
            first_name: formData.get('first_name'),
            middle_name: formData.get('middle_name'),
            last_name: formData.get('last_name'),
            email: formData.get('email'),
            mobile: formData.get('mobile'),
            dob: formData.get('dob'),
            country: formData.get('country'),
            state: formData.get('state'),
            city: formData.get('city')
        };

        try {
            const res = await fetch(`${API_BASE}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await res.json();

            if (!res.ok) {
                let errorMsg = 'Registration failed.';
                if (data.detail) {
                    if (Array.isArray(data.detail)) {
                        errorMsg = data.detail.map(err => typeof err === 'object' ? (err.msg || JSON.stringify(err)) : err).join(', ');
                    } else if (typeof data.detail === 'object') {
                        errorMsg = JSON.stringify(data.detail);
                    } else {
                        errorMsg = data.detail;
                    }
                }
                throw new Error(errorMsg);
            }

            regSuccess.textContent = 'Administrator account created successfully! Redirecting to login...';
            regSuccess.classList.remove('hidden');
            
            setTimeout(() => {
                window.location.href = 'index.html';
            }, 2500);

        } catch (err) {
            regError.textContent = err.message;
            regError.classList.remove('hidden');
            submitBtn.innerHTML = '<i class="fas fa-check-circle"></i> Submit Registration';
            submitBtn.disabled = false;
        }
    });
});
