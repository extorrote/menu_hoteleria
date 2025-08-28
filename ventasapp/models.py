from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator 
from decimal import Decimal
from datetime import timedelta,datetime #ESTO ES PARA PODER MOSTRAR SI ESTA ABIERTO O NO
# ---------- Constants ----------

# CIUDADES PARA QUE EL USUARIO SELECCIONE
CITIES = [
    ('puerto_vallarta', 'Puerto Vallarta'),
    ('cancun', 'Cancún'),
    ('cabo_sanlucas', 'Cabo San Lucas'),
]


# Array de categorías con sus tipos de negocio asociados
CATEGORY_TYPES = {
    'gastronomia_bebidas': [
        ('restaurantes_formales', 'Restaurante Formal'),
        ('comida_rapida', 'Comida Rápida'),
        ('fondas_locales', 'Fonda o Comida Casera'),
        ('cafeterias', 'Cafetería'),
        ('panaderias_reposterias', 'Panadería o Pasteleria'),
        ('food_trucks', 'Food Truck'),
        ('licorerias', 'Licorería'),
        ('tiendas_helados_postres', 'Helados y Postres'),
        ('tiendas_saludables', 'Comida Saludable'),
        ('comida_vegana', 'Comida Vegana'),
        ('polleria', 'Polleria'),
    ],
    'tiendas_de_conveniencia': [
        ('tiendas_locales_de_abarrotes', 'Tienda Local de Abarrotes'),              
    ],
    'farmacias':[
        ('medicamentos', 'Medicamentos y otros Productos de Farmacia'),
    ],
    'flores_y_regalos': [
        ('tiendas_de_flores', 'Tiendas de flores'),
        ('tiendas_de_regalos', 'Tiendas de regalos'),
    ],
}

ALL_CATEGORY_TYPES = []
for cat_list in CATEGORY_TYPES.values():
    ALL_CATEGORY_TYPES.extend(cat_list)


from django.db import models
from datetime import datetime

# Choices para los días de la semana
DAYS_OF_WEEK = [
    ('mon', 'Lunes'),
    ('tue', 'Martes'),
    ('wed', 'Miércoles'),
    ('thu', 'Jueves'),
    ('fri', 'Viernes'),
    ('sat', 'Sábado'),
    ('sun', 'Domingo'),
]

class Business(models.Model):
    TIME_CATEGORY = [
        ('diurno', 'Diurno'),
        ('nocturno', 'Nocturno'),
        ('24_horas', '24 Horas'),
        
    ]
    is_active = models.BooleanField(default=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='businesses', null=True, blank=True)
    commercial_name = models.CharField(max_length=100)
    city = models.CharField(max_length=50, choices=CITIES)
    time_category = models.CharField(max_length=20, choices=TIME_CATEGORY, default='diurno')
    opening_time = models.TimeField()
    closing_time = models.TimeField()
    closed_days = models.TextField(
        blank=True,
        help_text="Días de la semana en los que el negocio está cerrado, separados por comas. Ej: mon,tue,sun"
    )
    # Ahora en tu modelo:
    tipos_de_negocio = models.CharField(max_length=200, choices=ALL_CATEGORY_TYPES)
    manager_name = models.CharField(max_length=100)
    owner_or_manager_whatsapp = models.CharField(max_length=20)
    owner_or_manager_email = models.EmailField()
    reservations_contact_name = models.CharField(max_length=100)
    reservations_whatsapp = models.CharField(max_length=20)
    reservations_email = models.EmailField()
    current_promotions = models.CharField(max_length=1000, blank=True, null=True)
    acepta_tarjeta = models.BooleanField(default=True, verbose_name="¿Acepta pagos con tarjeta?")
    acepta_efectivo = models.BooleanField(default=True, verbose_name="¿Acepta pagos en efectivo?")
    
    # CAMPO REMOVIDO - ya no necesario para hotel
    # hace_delivery = models.BooleanField(...)  # ELIMINADO
    
    # Media fields
    image1 = models.ImageField(upload_to='businesses/', null=True, blank=True)
    image2 = models.ImageField(upload_to='businesses/', null=True, blank=True)
    image3 = models.ImageField(upload_to='businesses/', null=True, blank=True)
    image4 = models.ImageField(upload_to='businesses/', null=True, blank=True)
    # Location fields
    address = models.CharField(max_length=255)
    
    website = models.URLField(blank=True, null=True)
    description = models.TextField()
    google_maps = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.commercial_name} ({self.city})"

    def get_tipos_display(self):
        if not self.tipos_de_negocio:
            return []
        codes = self.tipos_de_negocio.split(',')
        result = []
        for category in CATEGORY_TYPES.values():
            for code, label in category:
                if code in codes:
                    result.append(label)
        return result

    def get_closed_days_display(self):
        if not self.closed_days:
            return []
        codes = self.closed_days.split(',')
        return [label for code, label in DAYS_OF_WEEK if code in codes]

    def is_open_now(self):
        now = datetime.now()
        current_day = now.strftime('%a').lower()[:3]  # e.g., 'mon'
        current_time = now.time()

        # Convert closed_days into a list for comparison
        closed_days = [day.strip() for day in self.closed_days.split(',') if day.strip()]

        # If the business is closed today
        if current_day in closed_days:
            return False

        # 24-hour format handling
        if self.opening_time == self.closing_time:
            return True  # Open 24 hours

        # Handle overnight schedules, e.g., 10 PM - 4 AM
        if self.closing_time < self.opening_time:
            return current_time >= self.opening_time or current_time <= self.closing_time

        # Normal business hours
        return self.opening_time <= current_time <= self.closing_time


# models.py
class BusinessSubscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    stripe_subscription_id = models.CharField(max_length=255)
    stripe_customer_id = models.CharField(max_length=255)
    business = models.OneToOneField('Business', on_delete=models.SET_NULL, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)


SUBCATEGORY_CHOICES = []
for category_list in CATEGORY_TYPES.values():
    for subcat in category_list:
        SUBCATEGORY_CHOICES.append(subcat)

class Producto(models.Model):
    business = models.ForeignKey('Business', on_delete=models.CASCADE, related_name='productos')
    
    tipo_subcategoria = models.CharField(
        max_length=100,
        choices=SUBCATEGORY_CHOICES,
        default='comida_rapida',null=True,blank=True
    )
    
    name = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True, default=0)
    
    ingredientes=models.TextField(blank=True,null=True)
    image1 = models.ImageField(upload_to='productos/', null=True, blank=True)
    image2 = models.ImageField(upload_to='productos/', null=True, blank=True)
    image3 = models.ImageField(upload_to='productos/', null=True, blank=True)
    image4 = models.ImageField(upload_to='productos/', null=True, blank=True)
    tiene_envio_gratis=models.BooleanField(default=False)
    description = models.TextField(blank=True,null=True)
    disponible_para_pedido = models.BooleanField(default=True, verbose_name="Disponible para pedidos")
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} ({self.business.commercial_name})"

    def get_stripe_account_id(self):
        return self.business.stripe_id

## ESTE LO AGREGUE PARA EXTRAS DE LOS PRODUCTOS
class Extra(models.Model):
    producto = models.ForeignKey(Producto, on_delete=models.CASCADE, related_name='extras')
    nombre = models.CharField(max_length=100, verbose_name="Nombre del Extra")
    precio = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))],
        verbose_name="Precio del Extra (MXN)"
    )

    def __str__(self):
        return f"{self.nombre} - {self.producto.name}" 


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('business_owner', 'Propietario de Negocio'),
        ('conductor', 'Conductor'),
    ]
    company_name = models.CharField(max_length=255, blank=True, null=True,verbose_name='Nombre de Compañia')
    giro_de_negocio = models.CharField(max_length=150,choices=SUBCATEGORY_CHOICES,null=True,blank=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE,verbose_name='Usuario')
    tu_nombre = models.CharField(max_length=255, blank=True, null=True,verbose_name='Nombre')
    last_name = models.CharField(max_length=255, blank=True, null=True,verbose_name='Apellidos')
    telephone = models.CharField(max_length=20, blank=True, null=True,verbose_name='Telefono')
    email = models.EmailField(blank=True, null=True, verbose_name='Correo Electrónico')
    profile_picture = models.ImageField(upload_to='profiles/', null=True, blank=True,verbose_name='Foto de Perfil')
    id_document = models.ImageField(upload_to='ids/', blank=True, null=True,verbose_name='Documento de Identidad')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='conductor',verbose_name='Rol')
    city = models.CharField(max_length=50, choices=CITIES,verbose_name='Ciudad', default="puerto_vallarta")
    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)#ESTO LO AGREGAMOS PARA EL TEMA DE LAS MEMBRESIAS
    stripe_secret_key = models.CharField(max_length=655, blank=True, null=True)#EL ENCRYPTED ES PARA QUE NO SE VEA LA CLAVE Y NO CORRA RIESGOS

    #ESTO LO AGUEGUE PARA PODER MOSTRAR EL EMAIL QUE ESTOY SOLICITANDO EN FORMS PERO NO ES EL DE ESTE MODELO EN SI SINO EL DEL MODELO User
    def save(self, *args, **kwargs):
        # Sync email field with user model before saving
        self.email = self.user.email#ESTO LO HICE PARA QUE ESTOS CAMPOS APAREZCAN EN MI MODELO UserProfile pero en el form los estoy pidiendo del modelo User
        self.tu_nombre=self.user.first_name
        self.last_name=self.user.last_name
        super().save(*args, **kwargs)
        
    def __str__(self):
        return f"{self.user.username} ({self.role})"   


class ConductorUser(models.Model):
    TIPO_VEHICULO_CHOICES = [
        ('auto', 'Automóvil'),
        ('moto', 'Motocicleta'),
        ('bicicleta', 'Bicicleta'),
        ('pie', 'A pie'),
    ]
    
    ROLE_CHOICES = [
        ('business_owner', 'Propietario de Negocio'),
        ('conductor', 'Conductor'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='concierge',verbose_name='Rol')

    user = models.OneToOneField(User, on_delete=models.CASCADE, verbose_name='Usuario',null=True,blank=True)
    
    # Información personal
    fecha_nacimiento =  models.CharField(max_length=100)
    nacionalidad = models.CharField(max_length=100)
    curp = models.CharField(max_length=18, unique=True)

    # Información de contacto
    telefono = models.CharField(max_length=15)
    direccion = models.CharField(max_length=100)
    city = models.CharField(max_length=50, choices=CITIES,verbose_name='Ciudad',blank=True,default=True)
    estado = models.CharField(max_length=100)
    codigo_postal = models.CharField(max_length=10)

    # Documentación legal
    licencia_numero = models.CharField(max_length=20)
    licencia_fecha_emision = models.CharField(max_length=100)
    licencia_fecha_vencimiento = models.CharField(max_length=100)
    licencia_tipo = models.CharField(max_length=50)
    identificacion_oficial = models.FileField(upload_to='documentos/identificaciones/')
    comprobante_domicilio = models.FileField(upload_to='documentos/comprobantes/')

    # Información del vehículo
    tipo_vehiculo = models.CharField(max_length=20, choices=TIPO_VEHICULO_CHOICES)
    marca_vehiculo = models.CharField(max_length=50, blank=True, null=True)
    modelo_vehiculo = models.CharField(max_length=50, blank=True, null=True)
    anio_vehiculo = models.PositiveIntegerField(blank=True, null=True)
    placas = models.CharField(max_length=20, blank=True, null=True)
    color_vehiculo = models.CharField(max_length=30, blank=True, null=True)
    tarjeta_circulacion = models.FileField(upload_to='documentos/tarjetas_circulacion/', blank=True, null=True)
    seguro_vehiculo = models.FileField(upload_to='documentos/seguros/', blank=True, null=True)

    # Método de pago
    cuenta_bancaria = models.CharField(max_length=30)
    clabe = models.CharField(max_length=18)
    banco = models.CharField(max_length=100)
    titular_cuenta = models.CharField(max_length=100)

    # Disponibilidad
    zonas_operacion = models.CharField(max_length=200)
    dias_disponibles = models.CharField(max_length=100)
    horarios_disponibles = models.CharField(max_length=100)

    # Documentación adicional
    antecedentes_penales = models.FileField(upload_to='documentos/antecedentes/', blank=True, null=True)
    foto_selfie = models.ImageField(upload_to='documentos/fotos/')
    firma_digital = models.FileField(upload_to='documentos/firmas/', blank=True, null=True)

    # Campos de seguridad/verificación
    is_approved = models.BooleanField(default=False,verbose_name='Aprobado/Sin Aprobar')
    fecha_registro = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user.get_full_name()} ({self.user.username})'
 

# OPCIONES ACTUALIZADAS PARA HOTEL
OPCIONES_ENTREGA = [
    ('roomservice', 'Room Service - Entrega en habitación'),
    ('restaurante', 'Bajar al restaurante'),
]

class DireccionDeEnvio(models.Model):
    # OPCIÓN DE ENTREGA ACTUALIZADA
    opcion_entrega = models.CharField(
        max_length=100,
        choices=OPCIONES_ENTREGA,
        default='roomservice',
        verbose_name='¿Room Service o bajar al restaurante?'
    )
    
    # DATOS BÁSICOS DEL HUÉSPED
    nombre_completo = models.CharField(max_length=255)
    telefono = models.CharField(max_length=20)
    
    # CAMPOS ESPECÍFICOS PARA HOTEL
    numero_habitacion = models.CharField(
        max_length=20, 
        blank=True, 
        null=True, 
        verbose_name="Número de habitación"
    )
  
    
    
    
    
    # PROPINA
    propina_voluntaria = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        blank=True, 
        null=True,
        verbose_name="Propina"
    )
    decidir_propina_despues = models.BooleanField(
        default=False,
        verbose_name='Decidir propina después'
    )
    
    # NOTAS ESPECIALES
    notas = models.TextField(default="", blank=True, null=True)
    
    
    
    fecha_creacion = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.opcion_entrega == 'roomservice' and self.numero_habitacion:
            return f'{self.nombre_completo} - Habitación {self.numero_habitacion}'
        else:
            return f'{self.nombre_completo} - Restaurante'


from django.db import models
from decimal import Decimal
from django.contrib.auth.models import User

# -------- MODELOS DE CARRITO --------

class Cart(models.Model):
    session_key = models.CharField(max_length=40, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Carrito {self.session_key}"


class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='items')
    producto = models.ForeignKey('Producto', on_delete=models.CASCADE)
    cantidad = models.PositiveIntegerField(default=1)
    nota = models.TextField(blank=True, null=True)
    
    def subtotal(self):
        total = self.producto.price * self.cantidad
        for extra_item in self.extras_en_carrito.all():
            total += extra_item.subtotal()
        return total

    def __str__(self):
        return f"{self.producto.name} x{self.cantidad}"


class ExtraEnCarrito(models.Model):
    cart_item = models.ForeignKey(CartItem, on_delete=models.CASCADE, related_name='extras_en_carrito')
    extra = models.ForeignKey('Extra', on_delete=models.CASCADE)
    cantidad = models.PositiveIntegerField(default=1)

    def subtotal(self):
        return self.extra.precio * self.cantidad

    def __str__(self):
        return f"{self.extra.nombre} x{self.cantidad} (Carrito Item ID: {self.cart_item.id})"
    

# -------- MODELOS DE PEDIDO Y VENTA --------

class Pedido(models.Model):
    # MÉTODOS DE PAGO ACTUALIZADOS PARA HOTEL
    METODOS_PAGO = [
        ('tarjeta', 'Tarjeta de crédito/débito'),
        ('efectivo', 'Efectivo al recibir'),
        ('habitacion', 'Cargo a habitación'),  # NUEVA OPCIÓN
    ]

    cliente = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    direccion_envio = models.ForeignKey('DireccionDeEnvio', on_delete=models.SET_NULL, null=True, blank=True)
    fecha = models.DateTimeField(auto_now_add=True)
    pagado = models.BooleanField(default=False)
    enviado = models.BooleanField(default=False)
    total_pagado = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    session_key = models.CharField(max_length=100, null=True, blank=True)

    metodo_pago = models.CharField(
        max_length=20,
        choices=METODOS_PAGO,
        default='tarjeta',
        verbose_name="Método de pago"
    )

    def __str__(self):
        return f"Pedido #{self.id} - {self.fecha.strftime('%Y-%m-%d')}"

    def calcular_total(self):
        return sum(venta.subtotal for venta in self.ventas.all())

    class Meta:
        verbose_name = "Lista de Pedidos"
        verbose_name_plural = "Lista de Pedidos"


class Venta(models.Model):
    pedido = models.ForeignKey(Pedido, on_delete=models.CASCADE, related_name='ventas', null=True, blank=True)
    business = models.ForeignKey('Business', on_delete=models.CASCADE, related_name='ventas')
    producto = models.ForeignKey('Producto', on_delete=models.SET_NULL, null=True)
    cantidad = models.PositiveIntegerField()
    precio_unitario = models.DecimalField(max_digits=10, decimal_places=2)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)

    direccion_envio = models.ForeignKey('DireccionDeEnvio', on_delete=models.SET_NULL, null=True, blank=True)
    cliente = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    pagado = models.BooleanField(default=False)
    enviado = models.BooleanField(default=False)
    nota = models.TextField(blank=True, null=True) 
    fecha = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.producto.name} x{self.cantidad} - {self.business.commercial_name}"

    def calcular_subtotal_completo(self):
        total = self.subtotal  # subtotal base del producto * cantidad
        for extra in self.extras_en_venta.all():
            total += extra.subtotal()
        return total

    class Meta:
        verbose_name = "Producto Vendido por separado"
        verbose_name_plural = "Productos Vendidos por separado"


class ExtraEnVenta(models.Model):
    venta = models.ForeignKey(Venta, on_delete=models.CASCADE, related_name='extras_en_venta')
    extra = models.ForeignKey(Extra, on_delete=models.CASCADE)
    cantidad = models.PositiveIntegerField(default=1)

    def subtotal(self):
        return self.extra.precio * self.cantidad