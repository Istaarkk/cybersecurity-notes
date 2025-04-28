document.addEventListener('DOMContentLoaded', () => {
    // Add copy buttons to all code blocks
    document.querySelectorAll('pre code').forEach((block) => {
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.innerHTML = '<i class="fas fa-copy"></i>';
        
        // Add click event
        button.addEventListener('click', async () => {
            const code = block.textContent;
            try {
                await navigator.clipboard.writeText(code);
                button.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => {
                    button.innerHTML = '<i class="fas fa-copy"></i>';
                }, 2000);
            } catch (err) {
                console.error('Failed to copy code:', err);
                button.innerHTML = '<i class="fas fa-times"></i>';
                setTimeout(() => {
                    button.innerHTML = '<i class="fas fa-copy"></i>';
                }, 2000);
            }
        });
        
        // Add button to pre element
        block.parentElement.style.position = 'relative';
        block.parentElement.appendChild(button);
    });
}); 