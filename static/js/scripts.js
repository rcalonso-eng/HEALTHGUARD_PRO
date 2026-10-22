// scripts.js

function confirmarEliminar(url, mensaje = '¿Estás seguro de eliminar este elemento?') {
    if (confirm(mensaje)) {
        window.location.href = url;
    }
}

// Para los enlaces de eliminar en las tablas (se puede usar data-url)
document.addEventListener('DOMContentLoaded', function() {
    const deleteLinks = document.querySelectorAll('.btn-delete[data-url]');
    deleteLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const url = this.dataset.url;
            const message = this.dataset.message || '¿Estás seguro?';
            if (confirm(message)) {
                window.location.href = url;
            }
        });
    });

    // Auto-cerrar alertas después de 5 segundos
    const alerts = document.querySelectorAll('.alert-glass');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.display = 'none';
        }, 5000);
    });
});