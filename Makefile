.PHONY: help serve build clean new-writeup new-article deploy scripts-exec

# Couleurs pour l'affichage
GREEN := \033[32m
BLUE := \033[34m
YELLOW := \033[33m
RED := \033[31m
NC := \033[0m # No Color

# Configuration
HUGO_VERSION := latest
PORT := 1313
HOST := localhost

help: ## Affiche l'aide
	@echo "$(BLUE)🔒 WriteUps & Cybersécurité - Commands$(NC)"
	@echo "$(BLUE)=====================================$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

serve: ## Lance le serveur de développement
	@echo "$(BLUE)🚀 Lancement du serveur Hugo...$(NC)"
	@echo "$(YELLOW)   URL: http://$(HOST):$(PORT)$(NC)"
	@echo "$(YELLOW)   Ctrl+C pour arrêter$(NC)"
	hugo server -D --bind $(HOST) --port $(PORT) --navigateToChanged

serve-public: ## Lance le serveur accessible publiquement
	@echo "$(BLUE)🌐 Lancement du serveur public...$(NC)"
	hugo server -D --bind 0.0.0.0 --port $(PORT) --navigateToChanged

build: ## Compile le site pour la production
	@echo "$(BLUE)🔨 Compilation du site...$(NC)"
	hugo --gc --minify
	@echo "$(GREEN)✅ Site compilé dans ./public/$(NC)"

build-draft: ## Compile le site avec les brouillons
	@echo "$(BLUE)🔨 Compilation avec brouillons...$(NC)"
	hugo -D --gc --minify
	@echo "$(GREEN)✅ Site compilé dans ./public/$(NC)"

clean: ## Nettoie les fichiers générés
	@echo "$(BLUE)🧹 Nettoyage...$(NC)"
	rm -rf public/
	rm -rf resources/_gen/
	rm -rf .hugo_build.lock
	@echo "$(GREEN)✅ Nettoyage terminé$(NC)"

new-writeup: scripts-exec ## Crée un nouveau writeup interactivement
	@echo "$(BLUE)📝 Création d'un nouveau writeup...$(NC)"
	@./scripts/new-writeup.sh

new-article: scripts-exec ## Crée un nouvel article (veille, outils, etc.)
	@echo "$(BLUE)📄 Création d'un nouvel article...$(NC)"
	@./scripts/new-article.sh

scripts-exec: ## Rend les scripts exécutables
	@chmod +x scripts/*.sh

install: ## Installe Hugo (si pas déjà installé)
	@if ! command -v hugo >/dev/null 2>&1; then \
		echo "$(YELLOW)⚠️  Hugo n'est pas installé$(NC)"; \
		echo "$(BLUE)Installation de Hugo...$(NC)"; \
		if command -v brew >/dev/null 2>&1; then \
			brew install hugo; \
		elif command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install hugo; \
		elif command -v yum >/dev/null 2>&1; then \
			sudo yum install hugo; \
		else \
			echo "$(RED)❌ Impossible d'installer Hugo automatiquement$(NC)"; \
			echo "$(YELLOW)Visitez: https://gohugo.io/installation/$(NC)"; \
			exit 1; \
		fi; \
	else \
		echo "$(GREEN)✅ Hugo est déjà installé$(NC)"; \
		hugo version; \
	fi

check: ## Vérifie la configuration et les erreurs
	@echo "$(BLUE)🔍 Vérification du site...$(NC)"
	@echo "$(YELLOW)Version Hugo:$(NC)"
	@hugo version
	@echo ""
	@echo "$(YELLOW)Configuration:$(NC)"
	@hugo config
	@echo ""
	@echo "$(YELLOW)Pages:$(NC)"
	@hugo list all

stats: ## Affiche les statistiques du site
	@echo "$(BLUE)📊 Statistiques du site$(NC)"
	@echo "$(BLUE)=======================$(NC)"
	@echo "$(GREEN)WriteUps:$(NC) $$(find content/writeups -name "*.md" | wc -l)"
	@echo "$(GREEN)Articles de veille:$(NC) $$(find content/veille -name "*.md" 2>/dev/null | wc -l || echo 0)"
	@echo "$(GREEN)Outils:$(NC) $$(find content/outils -name "*.md" 2>/dev/null | wc -l || echo 0)"
	@echo "$(GREEN)Total pages:$(NC) $$(find content -name "*.md" | wc -l)"
	@echo "$(GREEN)Images:$(NC) $$(find static/images -type f 2>/dev/null | wc -l || echo 0)"
	@echo "$(GREEN)CSS personnalisés:$(NC) $$(find static/css -name "*.css" 2>/dev/null | wc -l || echo 0)"

lint: ## Vérifie la syntaxe des fichiers markdown
	@echo "$(BLUE)🔍 Vérification de la syntaxe...$(NC)"
	@if command -v markdownlint >/dev/null 2>&1; then \
		markdownlint content/**/*.md; \
		echo "$(GREEN)✅ Syntaxe markdown OK$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  markdownlint non installé (npm install -g markdownlint-cli)$(NC)"; \
	fi

deploy-gh: build ## Déploie sur GitHub Pages (si configuré)
	@echo "$(BLUE)🚀 Déploiement sur GitHub Pages...$(NC)"
	@if [ -d .git ]; then \
		git add .; \
		git commit -m "Deploy: $$(date '+%Y-%m-%d %H:%M:%S')"; \
		git push origin main; \
		echo "$(GREEN)✅ Déployé sur GitHub Pages$(NC)"; \
	else \
		echo "$(RED)❌ Pas un dépôt Git$(NC)"; \
	fi

quick-post: ## Création rapide d'un post (titre en argument)
ifndef TITLE
	@echo "$(RED)❌ Usage: make quick-post TITLE=\"Mon titre\"$(NC)"
else
	@echo "$(BLUE)⚡ Création rapide...$(NC)"
	@hugo new "writeups/$$(date +%Y-%m-%d)-$$(echo "$(TITLE)" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g').md"
	@echo "$(GREEN)✅ Post créé$(NC)"
endif

dev: serve ## Alias pour serve

watch: ## Lance Hugo en mode watch (rebuild automatique)
	@echo "$(BLUE)👀 Mode watch activé...$(NC)"
	hugo server -D --watch --disableFastRender

backup: ## Sauvegarde le contenu
	@echo "$(BLUE)💾 Sauvegarde...$(NC)"
	@tar -czf "backup-$$(date +%Y%m%d-%H%M%S).tar.gz" content/ static/ layouts/ config.yaml
	@echo "$(GREEN)✅ Sauvegarde créée$(NC)"

setup: install scripts-exec ## Configuration initiale complète
	@echo "$(BLUE)🔧 Configuration initiale...$(NC)"
	@echo "$(GREEN)✅ Configuration terminée !$(NC)"
	@echo ""
	@echo "$(YELLOW)Commandes utiles:$(NC)"
	@echo "  make serve          - Lance le serveur de dev"
	@echo "  make new-writeup    - Crée un writeup"
	@echo "  make new-article    - Crée un article"
	@echo "  make build          - Compile le site"
	@echo ""
	@echo "$(GREEN)🎉 Prêt à écrire !$(NC)"

# Tâche par défaut
default: help 