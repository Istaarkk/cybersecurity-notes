document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('search-input');
    const searchButton = document.getElementById('search-button');
    const searchResults = document.getElementById('search-results');
    const searchPlaceholder = document.querySelector('.search-placeholder');
    
    // Configuration de Fuse.js
    const fuseOptions = {
        keys: ['title', 'content', 'tags'],
        threshold: 0.3,
        includeScore: true
    };
    
    let fuse;
    
    // Initialiser Fuse.js avec l'index de recherche
    if (window.searchIndex && window.searchIndex.length > 0) {
        fuse = new Fuse(window.searchIndex, fuseOptions);
    }
    
    // Fonction de recherche
    function performSearch() {
        const query = searchInput.value.trim();
        
        if (!query) {
            searchResults.innerHTML = '<p class="search-placeholder">Entrez un terme de recherche pour commencer...</p>';
            return;
        }
        
        if (!fuse) {
            searchResults.innerHTML = '<p class="no-results">Aucun contenu disponible pour la recherche.</p>';
            return;
        }
        
        const results = fuse.search(query);
        
        if (results.length === 0) {
            searchResults.innerHTML = '<p class="no-results">Aucun résultat trouvé pour "' + query + '".</p>';
            return;
        }
        
        let resultsHTML = '<h2>Résultats pour "' + query + '" (' + results.length + ')</h2>';
        resultsHTML += '<ul class="search-results-list">';
        
        results.slice(0, 10).forEach(result => {
            const item = result.item;
            const score = result.score;
            const relevance = score < 0.1 ? 'Très pertinent' : (score < 0.3 ? 'Pertinent' : 'Moins pertinent');
            
            resultsHTML += `
                <li class="search-result-item">
                    <h3><a href="${item.url}">${item.title}</a></h3>
                    <div class="search-result-meta">
                        <span class="search-result-section">${item.section}</span>
                        <span class="search-result-date">${item.date}</span>
                        <span class="search-result-relevance">${relevance}</span>
                    </div>
                    <div class="search-result-excerpt">
                        ${getExcerpt(item.content, query)}
                    </div>
                    ${item.tags ? `
                        <div class="search-result-tags">
                            ${item.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
                        </div>
                    ` : ''}
                </li>
            `;
        });
        
        resultsHTML += '</ul>';
        
        if (results.length > 10) {
            resultsHTML += `<p class="more-results">Et ${results.length - 10} autres résultats...</p>`;
        }
        
        searchResults.innerHTML = resultsHTML;
    }
    
    // Extraire un extrait de texte contenant le terme de recherche
    function getExcerpt(content, query) {
        const words = content.split(/\s+/);
        const queryWords = query.toLowerCase().split(/\s+/);
        
        // Trouver la première occurrence d'un mot de recherche
        let startIndex = -1;
        for (let i = 0; i < words.length; i++) {
            if (queryWords.some(qw => words[i].toLowerCase().includes(qw))) {
                startIndex = i;
                break;
            }
        }
        
        if (startIndex === -1) {
            // Si aucun mot de recherche n'est trouvé, prendre le début du contenu
            return content.substring(0, 200) + '...';
        }
        
        // Prendre 50 mots avant et 50 mots après
        const start = Math.max(0, startIndex - 50);
        const end = Math.min(words.length, startIndex + 50);
        
        let excerpt = words.slice(start, end).join(' ');
        
        // Ajouter des ellipses si nécessaire
        if (start > 0) excerpt = '...' + excerpt;
        if (end < words.length) excerpt += '...';
        
        return excerpt;
    }
    
    // Événements
    searchButton.addEventListener('click', performSearch);
    searchInput.addEventListener('keyup', function(e) {
        if (e.key === 'Enter') {
            performSearch();
        }
    });
}); 