
(function() {
    // Сохраняем оригинальный fetch
    const originalFetch = window.fetch;

    if (!originalFetch) {
        console.warn('[CSRF] Native fetch not found, skipping CSRF protection');
        return;
    }

    // CSRF Token Manager
    const CSRF = {
        getToken() {
            const metaTag = document.querySelector('meta[name="csrf-token"]');
            if (metaTag) {
                const content = metaTag.getAttribute('content');
                if (content) {
                    console.log('[CSRF] Token found in meta tag:', content.substring(0, 20) + '...');
                    return content;
                }
            }
            // Fallback: получить из cookie
            const cookieToken = this.getCookie('csrf_token');
            if (cookieToken) {
                console.log('[CSRF] Token found in cookie:', cookieToken.substring(0, 20) + '...');
            }
            return cookieToken;
        },

        // Получить JWT токен из localStorage
        getAuthToken() {
            try {
                const token = localStorage.getItem('token');
                if (token) {
                    console.log('[CSRF] Auth token found in localStorage');
                }
                return token;
            } catch (e) {
                console.debug('[CSRF] localStorage read error:', e);
            }
            return null;
        },

        // Получить cookie по имени
        getCookie(name) {
            try {
                const value = `; ${document.cookie}`;
                const parts = value.split(`; ${name}=`);
                if (parts.length === 2) {
                    return parts.pop().split(';').shift();
                }
            } catch (e) {
                console.debug('[CSRF] Cookie read error:', e);
            }
            return null;
        },

        async fetchWithCSRF(url, options = {}) {
            const token = this.getToken();
            const authToken = this.getAuthToken();

            const headers = {
                ...(options.headers || {}),
            };

            const method = (options.method || 'GET').toUpperCase();
            if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method) && token) {
                headers['X-CSRF-Token'] = token;
                console.log('[CSRF] Adding CSRF token to', method, url);
            }

            if (authToken) {
                headers['Authorization'] = `Bearer ${authToken}`;
                console.log('[CSRF] Adding auth token to', method, url);
            }

            console.log('[CSRF] Fetch request:', method, url, 'Headers:', headers);
            return originalFetch(url, {
                ...options,
                headers
            });
        }
    };

    window.fetch = function(url, options = {}) {
        if (typeof url === 'string') {
            return CSRF.fetchWithCSRF(url, options);
        }
        return originalFetch.call(this, url, options);
    };

    console.log('[CSRF] Protection initialized');
})();
