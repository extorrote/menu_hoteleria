document.addEventListener("DOMContentLoaded", function () {
    const swipers = document.querySelectorAll('.swiper');
    const botonnext = document.querySelector('.swiper-button-next');
    const botonprev = document.querySelector('.swiper-button-prev');
    botonnext.style.color = "transparent";
    botonprev.style.color = "transparent";

    swipers.forEach((swiperEl) => {
        new Swiper(swiperEl, {
            effect: 'fade',              // Efecto fade agregado
            fadeEffect: {
                crossFade: true,         // Transición suave
            },
            navigation: {
                nextEl: swiperEl.querySelector('.swiper-button-next'),
                prevEl: swiperEl.querySelector('.swiper-button-prev'),
            },
            loop: true,
            autoplay: {
                delay: 3000, // Cambia imagen cada 3 segundos
                disableOnInteraction: false, // Continúa autoplay tras interacción
            },
        });
    });
});

let lightbox = document.getElementById("lightbox");
let lightboxImg = document.getElementById("lightbox-img");
let images = [];
let currentIndex = 0;

// ✅ Actualizado: openLightbox ahora recibe el elemento para identificar el producto
function openLightbox(url, element) {
    // Buscar el contenedor del producto más cercano
    const swiperContainer = element.closest('.swiper-container');

    // Obtener solo las imágenes dentro de ese producto
    images = Array.from(swiperContainer.querySelectorAll("img")).map(img => img.src);

    // Obtener el índice de la imagen actual
    currentIndex = images.indexOf(url);

    // Mostrar la imagen en el lightbox
    lightboxImg.src = url;
    lightbox.style.display = "flex";
}

function closeLightbox() {
    lightbox.style.display = "none";
}

function changeLightbox(direction, event) {
    event.stopPropagation(); // Evita que el evento burbujee y cierre el modal
    currentIndex = (currentIndex + direction + images.length) % images.length;
    lightboxImg.src = images[currentIndex];
}

// CAMBIAR TEXTO DEL SUMMARY
const cambiarTexto = document.querySelector(".summary-info");
const defaultText = cambiarTexto.textContent;

cambiarTexto.addEventListener("click", () => {
    if (cambiarTexto.textContent === "Cerrar") {
        cambiarTexto.textContent = defaultText;
    } else {
        cambiarTexto.textContent = "Cerrar";
    }
});
