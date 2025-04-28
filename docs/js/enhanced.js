document.addEventListener('DOMContentLoaded', function() {
    // Ajouter un effet de surlignage pour la syntaxe
    hljs.highlightAll();
    
    // Ajouter des boutons de copie aux blocs de code
    document.querySelectorAll('pre code').forEach((block) => {
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.innerHTML = '<i class="fas fa-copy"></i>';
        
        const pre = block.parentNode;
        pre.style.position = 'relative';
        pre.insertBefore(button, pre.firstChild);
        
        button.addEventListener('click', () => {
            navigator.clipboard.writeText(block.textContent);
            button.innerHTML = '<i class="fas fa-check"></i>';
            setTimeout(() => {
                button.innerHTML = '<i class="fas fa-copy"></i>';
            }, 2000);
        });
    });
    
    // Ajouter une animation de défilement pour les ancres
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
                
                // Ajouter un effet de surlignage temporaire
                targetElement.classList.add('highlight-target');
                setTimeout(() => {
                    targetElement.classList.remove('highlight-target');
                }, 2000);
            }
        });
    });
    
    // Ajouter un bouton de retour en haut de page
    const backToTop = document.createElement('button');
    backToTop.className = 'back-to-top';
    backToTop.innerHTML = '<i class="fas fa-arrow-up"></i>';
    document.body.appendChild(backToTop);
    
    backToTop.addEventListener('click', () => {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
    
    // Gérer l'affichage du bouton de retour en haut de page
    window.addEventListener('scroll', () => {
        if (window.scrollY > 300) {
            backToTop.style.display = 'block';
        } else {
            backToTop.style.display = 'none';
        }
    });
    
    // Ajouter une animation lors du chargement des images
    document.querySelectorAll('img').forEach(img => {
        img.classList.add('lazy-load');
        img.addEventListener('load', () => {
            img.classList.add('loaded');
        });
    });
});