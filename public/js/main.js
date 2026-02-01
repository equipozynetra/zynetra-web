document.addEventListener('DOMContentLoaded', () => {
    
    // 1. VERIFICAR SESIÓN y TIPO DE USUARIO
    fetch('/api/session-status')
        .then(response => response.json())
        .then(data => {
            if (data.loggedIn) {
                // A) Poner la etiqueta (Dueño / Cliente)
                const logoContainer = document.querySelector('.logo-link');
                if (logoContainer) {
                    // Evitar duplicados si ya existe
                    if (!logoContainer.querySelector('.owner-badge') && !logoContainer.querySelector('.client-badge')) {
                        const badge = document.createElement('span');
                        
                        if (data.isOwner) {
                            badge.className = 'owner-badge';
                            badge.innerText = 'DUEÑO';
                        } else {
                            badge.className = 'client-badge';
                            badge.innerText = 'CLIENTE';
                        }
                        
                        logoContainer.appendChild(badge);
                    }
                }

                // B) Cambiar botón de navegación (SOLO SI NO ESTAMOS EN EL DASHBOARD)
                // Si estamos en /dashboard, queremos que el botón siga siendo "Cerrar Sesión" (definido en HTML)
                if (window.location.pathname !== '/dashboard') {
                    const navBtn = document.querySelector('.desktop-nav .btn');
                    if(navBtn) {
                        navBtn.innerText = 'Mi Dashboard';
                        navBtn.href = '/dashboard';
                    }
                }
            }
        })
        .catch(err => console.error("Error verificando sesión:", err));

    // 2. HEADER SCROLL
    const header = document.getElementById('header');
    if(header){
        window.addEventListener('scroll', () => {
            if (window.scrollY > 50) {
                header.style.padding = '15px 0';
                header.style.background = 'rgba(15, 23, 42, 0.95)';
                header.style.boxShadow = '0 4px 20px rgba(0,0,0,0.3)';
            } else {
                header.style.padding = '20px 0';
                header.style.background = 'rgba(15, 23, 42, 0.85)';
                header.style.boxShadow = 'none';
            }
        });
    }

    // 3. MENÚ MÓVIL
    const mobileToggle = document.getElementById('mobile-toggle');
    const mobileMenu = document.getElementById('mobile-menu');

    if (mobileToggle) {
        mobileToggle.addEventListener('click', () => {
            mobileMenu.classList.toggle('active');
            const spans = mobileToggle.querySelectorAll('span');
            if (mobileMenu.classList.contains('active')) {
                spans[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
                spans[1].style.opacity = '0';
                spans[2].style.transform = 'rotate(-45deg) translate(5px, -5px)';
            } else {
                spans[0].style.transform = 'none';
                spans[1].style.opacity = '1';
                spans[2].style.transform = 'none';
            }
        });
    }
});