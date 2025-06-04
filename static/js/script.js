document.addEventListener('DOMContentLoaded', () => {
    const leaveForm = document.querySelector('form[action="/dashboard"]');
    if (leaveForm) {
        leaveForm.addEventListener('submit', (e) => {
            const startDate = document.getElementById('start_date').value;
            const endDate = document.getElementById('end_date').value;
            
            if (startDate && endDate) {
                if (new Date(startDate) > new Date(endDate)) {
                    e.preventDefault();
                    alert('End date must be after start date.');
                }
            }
        });
    }
});