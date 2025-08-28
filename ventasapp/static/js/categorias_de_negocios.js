document.addEventListener('DOMContentLoaded', function () {
    const tipoDeNegocioField = document.getElementById('id_tipos_de_negocio');
    const allFields = document.querySelectorAll('.field-tipo_de_negocio, .field-number_or_bedroom_name, .field-floor_number, .field-elevador, .field-vista_primaria, .field-vista_secundaria, .field-balcony, .field-backyard, .field-bedrooms, .field-bathrooms, .field-numero_de_camas, .field-max_people, .field-children_under_12, .field-smoking_allowed, .field-pet_friendly, .field-hot_water, .field-air_conditioning, .field-gym, .field-piscina_publica, .field-private_swimming_pool, .field-jacuzzi, .field-wifi, .field-kitchen, .field-appliances, .field-horario_checking, .field-horario_checkout, .field-caja_fuerte, .field-minibar_incluido, .field-includes_breakfast, .field-parking');

    function toggleFields() {
        const selectedCategory = tipoDeNegocioField.value;
        allFields.forEach(field => {
            if (field.classList.contains(`field-${selectedCategory}`)) {
                field.style.display = 'block';
            } else {
                field.style.display = 'none';
            }
        });
    }

    tipoDeNegocioField.addEventListener('change', toggleFields);
    toggleFields(); // Initial call to set the correct state on page load
});



document.addEventListener("DOMContentLoaded", function() {
    const selectCategoria = document.getElementById("id_categoria");
    const allFieldGroups = document.querySelectorAll(".categoria-fields");

    function updateVisibleFields() {
        const selected = selectCategoria.value;
        allFieldGroups.forEach(group => {
            group.style.display = "none";
        });

        if (selected) {
            const activeFields = document.querySelectorAll(`.categoria-fields.${selected}`);
            activeFields.forEach(group => {
                group.style.display = "block";
            });
        }
    }

    // Initial trigger
    updateVisibleFields();

    // Bind change event
    selectCategoria.addEventListener("change", updateVisibleFields);
});