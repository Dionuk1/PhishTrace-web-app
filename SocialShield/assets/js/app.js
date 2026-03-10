// Simple front-end helpers for better UX.
document.addEventListener('DOMContentLoaded', () => {
    // Ask for confirmation before deleting blacklist entries.
    document.querySelectorAll('.js-confirm-delete').forEach((button) => {
        button.addEventListener('click', (event) => {
            const ok = window.confirm('Are you sure you want to delete this domain?');
            if (!ok) {
                event.preventDefault();
            }
        });
    });

    // Trim URL input to reduce accidental spaces during demos.
    const urlInput = document.querySelector('#url');
    if (urlInput) {
        urlInput.addEventListener('blur', () => {
            urlInput.value = urlInput.value.trim();
        });
    }

    // Toggle password visibility with the refreshed monkey control.
    document.querySelectorAll('[data-monkey-toggle]').forEach((button) => {
        const targetId = button.getAttribute('data-target');
        const input = targetId ? document.getElementById(targetId) : null;

        if (!input) {
            return;
        }

        button.addEventListener('click', () => {
            const nextVisible = input.type === 'password';
            input.type = nextVisible ? 'text' : 'password';
            button.setAttribute('aria-pressed', nextVisible ? 'true' : 'false');
            button.setAttribute('aria-label', nextVisible ? 'Hide password' : 'Show password');
            button.classList.remove('is-bouncing');
            void button.offsetWidth;
            button.classList.add('is-bouncing');
            button.classList.toggle('is-revealed', nextVisible);
        });

        button.addEventListener('animationend', () => {
            button.classList.remove('is-bouncing');
        });
    });
});
