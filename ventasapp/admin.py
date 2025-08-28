from django.contrib import admin
from django.utils.html import format_html, format_html_join
from .models import (
    Business, Producto, Extra, UserProfile, ConductorUser,
    DireccionDeEnvio, Cart, CartItem, Venta, Pedido, ExtraEnVenta
)

# Inline para mostrar Extras dentro de Venta (solo lectura)
class ExtraEnVentaInline(admin.TabularInline):
    model = ExtraEnVenta
    extra = 0
    readonly_fields = ('extra', 'cantidad', 'subtotal_extra')
    can_delete = False
    show_change_link = False
    fields = ('extra', 'cantidad', 'subtotal_extra')

    def subtotal_extra(self, obj):
        return obj.extra.precio * obj.cantidad
    subtotal_extra.short_description = "Subtotal Extra"


# Inline para mostrar Ventas dentro de Pedido, con extras inline en el mismo registro
class VentaInline(admin.TabularInline):
    model = Venta
    extra = 0
    readonly_fields = ('producto', 'cantidad', 'precio_unitario', 'subtotal', 'business', 'mostrar_extras')
    can_delete = False
    show_change_link = True
    fields = ('producto', 'cantidad', 'precio_unitario', 'subtotal', 'business', 'mostrar_extras')

    def mostrar_extras(self, obj):
        extras = obj.extras_en_venta.all()
        if not extras.exists():
            return format_html("<i>Sin extras</i>")
        return format_html_join(
            '',
            '<div style="margin-left: 10px;">- {}: Cantidad: {} | Precio unitario: {} | Subtotal: {}</div>',
            ((extra.extra.nombre, extra.cantidad, extra.extra.precio, extra.subtotal()) for extra in extras)
        )
    mostrar_extras.short_description = "Extras"


##ESTE ES EL QUE MUESTRA LOS PEDIDOS AGRUPADOS
@admin.register(Pedido)
class PedidoAdmin(admin.ModelAdmin):
    list_display = ('id', 'cliente', 'pagado', 'total_pagado', 'fecha', 'enviado', 'mostrar_direccion_envio')
    list_filter = ('pagado', 'fecha', 'enviado')
    search_fields = ('cliente__username', 'id')
    readonly_fields = ('total_pagado', 'fecha', 'mostrar_direccion_envio')
    inlines = [VentaInline]

    fieldsets = (
        (None, {
            'fields': ('cliente', 'pagado', 'enviado', 'total_pagado', 'fecha', 'session_key', 'mostrar_direccion_envio')
        }),
    )

    def mostrar_direccion_envio(self, obj):
        d = obj.direccion_envio
        if not d:
            return "-"
        return format_html(
            '<b>Dirección de Envío:</b><br>'
            'Nombre: {}<br>'
            'Teléfono: {}<br>'
            'Entrega: {}<br>'
            'Dirección: {}<br>'
            'Ciudad: {}<br>'
            'Estado: {}<br>'
            'Código postal: {}<br>'
            'Propina: {}',
            d.nombre_completo,
            d.telefono,
            d.get_opcion_entrega_display(),
            d.direccion,
            d.ciudad,
            d.estado,
            d.codigo_postal,
            d.propina_voluntaria,
        )
    mostrar_direccion_envio.short_description = "Dirección de Envío"

"""
@admin.register(Venta)
class VentaAdmin(admin.ModelAdmin):
    list_display = (
        'producto', 'cantidad', 'subtotal', 'cliente', 'business',
        'pagado', 'enviado', 'fecha'
    )
    list_filter = ('business', 'pagado', 'enviado', 'fecha')
    search_fields = ('producto__name', 'cliente__username', 'business__commercial_name')
    readonly_fields = (
        'producto', 'cantidad', 'precio_unitario', 'subtotal',
        'cliente', 'direccion_envio', 'fecha', 'business'
    )
    list_editable = ('enviado',)
    inlines = [ExtraEnVentaInline]  # Mostrar extras por venta
"""

@admin.register(Business)
class BusinessAdmin(admin.ModelAdmin):
    list_display = ('commercial_name', 'city', 'owner')


@admin.register(Producto)
class ProductoAdmin(admin.ModelAdmin):
    list_display = ('name', 'business', 'price')


@admin.register(Extra)
class ExtraAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'producto', 'precio')


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'city')


@admin.register(ConductorUser)
class ConductorUserAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'is_approved')


@admin.register(DireccionDeEnvio)
class DireccionDeEnvioAdmin(admin.ModelAdmin):
    list_display = ('nombre_completo', 'opcion_entrega', )


@admin.register(Cart)
class CartAdmin(admin.ModelAdmin):
    list_display = ('session_key', 'created_at')


@admin.register(CartItem)
class CartItemAdmin(admin.ModelAdmin):
    list_display = ('cart', 'producto', 'cantidad')


@admin.register(ExtraEnVenta)
class ExtraEnVentaAdmin(admin.ModelAdmin):
    list_display = ('venta', 'extra', 'cantidad', 'subtotal_extra')
    readonly_fields = ('subtotal_extra',)

    def subtotal_extra(self, obj):
        return obj.extra.precio * obj.cantidad
    subtotal_extra.short_description = "Subtotal Extra"
