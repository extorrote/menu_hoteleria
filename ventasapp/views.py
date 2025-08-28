# Django core imports
from django.shortcuts import render, redirect, get_object_or_404  
# Renderiza plantillas (render), redirige (redirect), obtiene objetos o da error 404 (get_object_or_404)
# Usado en casi todas las vistas: ej. ver_carrito, eliminar_producto_menu, iniciar_pago, checkout, success, ver_pedidos_por_negocio, etc.

from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest, HttpResponseForbidden  
# Respuestas HTTP comunes
# HttpResponse: iniciar_pago (mensaje error), checkout, marcar_envio_pedido (denegar), success (mensaje)
# JsonResponse: add_to_cart, actualizar_carrito_ajax, obtener_pedidos_pendientes
# HttpResponseForbidden: eliminar_extra, marcar_envio_pedido

from django.views.decorators.csrf import csrf_exempt  
# Exime vistas del chequeo CSRF (ej. webhooks o AJAX sin token)
# Usado en actualizar_carrito_ajax

from django.views.decorators.http import require_POST, require_http_methods  
# Restringe métodos HTTP permitidos
# require_POST: marcar_envio_pedido
# require_http_methods: eliminar_item_carrito (permite GET y POST)

from django.contrib.auth.decorators import login_required  
# Protege vistas para usuarios autenticados
# Usado en casi todas las vistas que requieren usuario: eliminar_producto_menu, iniciar_pago, ver_pedidos_por_negocio, success, etc.

from django.contrib.auth import authenticate, login, logout, update_session_auth_hash  
# Funciones de autenticación
# logout: logout_user
# update_session_auth_hash: change_password, edit_profile
# authenticate, login: no las usaste explícitamente en las vistas que mostraste

from django.contrib.auth.models import User  
# Modelo de usuario Django
# Usado indirectamente en vistas de perfil y registro (edit_profile, view_profile, etc.)

from django.contrib.auth.forms import PasswordChangeForm  
# Formulario para cambio de contraseña
# Usado en change_password y edit_profile (para cambiar contraseña)

from django.contrib import messages  
# Mensajes de éxito/error para el usuario
# Usado en vistas con feedback, ej. change_password, edit_profile, send_email

from django.core.mail import send_mail, EmailMultiAlternatives  
# Envío de emails simples y con HTML
# Usado en la vista send_email

from django.conf import settings  
# Acceso a configuración del proyecto
# Usado para Stripe (stripe.api_key), para urls absolute (request.build_absolute_uri)

from django.urls import reverse  
# Construcción de URLs reversas
# Podría usarse en algunas vistas para redirección, pero no visible explícitamente en el código que mostraste

from django.db.models import Q, Prefetch  
# Consultas avanzadas en la base de datos
# No lo usaste explícitamente en el código que mostraste, pero podría usarse para optimizar queries en vistas como ver_pedidos_por_negocio

# Stripe
import stripe  
# SDK de Stripe para pagos
# Usado en iniciar_pago, checkout para crear sesiones de pago

stripe.api_key = settings.STRIPE_SECRET_KEY  
# Configuración de clave secreta global para Stripe
# Se usa como default, pero luego se sobreescribe en iniciar_pago y checkout con la clave secreta del negocio

# Python core
import json  
# Manejo de JSON
# Usado en actualizar_carrito_ajax para parsear body JSON

from decimal import Decimal  
# Precisión en operaciones decimales
# Usado en todas las vistas que manejan precios, subtotales, propinas, costos de envío: iniciar_pago, checkout, success, ver_pedidos_por_negocio, direccion_envio

from collections import defaultdict  
# Estructura para agrupar elementos
# Usado en ver_pedidos_por_negocio para agrupar ventas por pedido

# Modelos propios
from .models import (
    Business, Producto, UserProfile, CATEGORY_TYPES, CITIES, DAYS_OF_WEEK,
    Extra, ConductorUser, BusinessSubscription, CartItem, Cart,
    ExtraEnCarrito, DireccionDeEnvio, Venta, Pedido, ExtraEnVenta
)
# Usados en casi todas las vistas donde manipulas datos:
# Business, Producto, Extra, CartItem, Cart, ExtraEnCarrito en carrito y menú
# DireccionDeEnvio en direccion_envio, iniciar_pago, checkout, success
# Venta, Pedido, ExtraEnVenta en success, ver_pedidos_por_negocio, marcar_envio_pedido
# UserProfile para obtener perfil y claves Stripe (iniciar_pago, checkout)

from .forms import DireccionDeEnvioForm,BusinessForm

def index(request):
    return render(request,'index.html')

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.templatetags.static import static  # Import necesario para construir URL del logo

def register_user(request, role):
    if role not in ['business_owner', 'concierge']:
        return redirect('home')

    if request.method == 'POST':
        user_form = UserRegistrationForm(request.POST)
        profile_form = BusinessOwnerProfileForm(request.POST, request.FILES)

        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save(commit=False)
            user.set_password(user_form.cleaned_data['password'])
            user.save()

            profile = profile_form.save(commit=False)
            profile.user = user
            profile.role = role
            profile.save()

            # Iniciar sesión automáticamente
            login(request, user)

            # Enviar correo de confirmación al usuario
            role_text = "Propietario de Negocio" if role == 'business_owner' else role.capitalize()
            subject = "¡Bienvenido a Sabor Local!"
            from_email = "noreply@saborlocalpv.com"
            to = [user.email]

            # Detectar si estás en localhost para evitar URLs inválidas
            if request.get_host().startswith('localhost') or request.get_host().startswith('127.0.0.1'):
                logo_url = "https://saborlocalpv.com/static/images/logo_redondo.png"
            else:
                logo_url = request.build_absolute_uri(static('images/logo_redondo.png'))

            context = {
                'nombre': user.first_name,
                'role': role_text,
                'username': user.username,
                'logo_url': logo_url,
            }

            html_content = render_to_string('confirmacion_registro.html', context)
            text_content = f"Hola {user.first_name}, gracias por registrarte como {role_text} en Sabor Local."

            msg = EmailMultiAlternatives(subject, text_content, from_email, to)
            msg.attach_alternative(html_content, "text/html")
            msg.send()

            return redirect('dashboard')

    else:
        user_form = UserRegistrationForm()
        profile_form = BusinessOwnerProfileForm()

    return render(request, 'register.html', {
        'user_form': user_form,
        'profile_form': profile_form,
        'role': role
    })

def registtrar_conductor(request, role):
    if request.method == 'POST':
        user_form = UserRegistrationForm(request.POST)
        profile_form = ConductorProfileForm(request.POST, request.FILES) 

        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save(commit=False)
            user.set_password(user_form.cleaned_data['password'])
            user.save()

            profile = profile_form.save(commit=False)
            profile.user = user
            profile.role = role
            
            profile.save()

            # Email content
            subject = "Registro de Nuevo Usuario"
            from_email = "noreply@yourdomain.com"
            to = ['saborlocalpv@gmail.com']
            text_content = f"Un nuevo {role} se ha registrado con el nombre de usuario: {user.username}. Requiere aprobación para acceder al sistema."
            html_content = f"""
            <p>Un nuevo <strong style="color:#48e;">{role}</strong> se ha registrado con el nombre de usuario: 
            <span style="color:red; font-weight:bold;">{user.username}</span> 
            Requiere aprobación para acceder al sistema.</p>
            """

            msg = EmailMultiAlternatives(subject, text_content, from_email, to)
            msg.attach_alternative(html_content, "text/html")
            msg.send()

            return render(request, 'registration_pending.html')

    else:
        user_form = UserRegistrationForm()
        profile_form = ConductorProfileForm()
        

    return render(request, 'register.html', {
        'user_form': user_form,
        'profile_form': profile_form,
        'role': role
    })

from .models import ConductorUser

def login_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('dashboard')  # Redirige al dashboard único
        else:
            messages.error(request, "Nombre de usuario o contraseña inválidos.")

    return render(request, 'index.html')

# ESTOS SON LOS LABELS PARA LOS BOTONES PORQUE LOS ESTAMOS METIENDO EN IN BUcle
CATEGORY_DISPLAY_NAMES = {
    'gastronomia_bebidas': 'Gastronomía / Bebidas',
    'tiendas_de_conveniencia': 'Tiendas y Abarrotes',
    'farmacias': 'Farmacias',
    'flores_y_regalos': 'Flores y Regalos',
}

@login_required
def dashboard(request):
    try:
        profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        try:
            profile = request.user.conductoruser
        except ConductorUser.DoesNotExist:
            return redirect('not_authorized')

    category_filter = request.GET.get('categoria')  # e.g. "tours_actividades"

    if profile.role == 'business_owner':
        businesses = Business.objects.filter(owner=request.user)
        return render(request, 'dashboard_business_owner.html', {
            'profile': profile,
            'businesses': businesses, 
            'selected_category': category_filter,
            'categories': CATEGORY_TYPES,
            'category_labels': CATEGORY_DISPLAY_NAMES,
        })

    elif profile.role == 'conductor':
        # ✅ Filtrar negocios por ciudad del conductor
        businesses = Business.objects.filter(city=profile.city)

        if category_filter:
            category_types = dict(CATEGORY_TYPES).get(category_filter, [])
            category_codes = [code for code, label in category_types]
            if category_codes:
                businesses = businesses.filter(
                    Q(tipos_de_negocio__iregex=r'\b(' + '|'.join(category_codes) + r')\b')
                )

        return render(request, 'dashboard2.html', {
            'profile': profile,
            'businesses': businesses,
            'selected_category': category_filter,
            'categories': CATEGORY_TYPES,
            'category_labels': CATEGORY_DISPLAY_NAMES,
        })

    else:
        return redirect('not_authorized')

def tienda(request):
    category_filter = request.GET.get('categoria')  # Ejemplo: "gastronomia_bebidas"

    # Obtener todos los negocios activos
    businesses = Business.objects.filter(is_active=True)

    # Si hay filtro por categoría, aplicarlo
    if category_filter:
        category_types = CATEGORY_TYPES.get(category_filter, [])
        category_codes = [code for code, _ in category_types]

        if category_codes:
            businesses = businesses.filter(
                Q(tipos_de_negocio__iregex=r'\b(' + '|'.join(category_codes) + r')\b')
            )

    return render(request, 'dashboard2.html', {
        'profile': None,
        'businesses': businesses,
        'selected_category': category_filter,
        'categories': CATEGORY_TYPES,
        'category_labels': CATEGORY_DISPLAY_NAMES,
    })

# ESTO LO ESTAMOS USANDO PARA LA SUSCRIPCION DEL NEGOCIO
@csrf_exempt
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = settings.STRIPE_WEBHOOK_SECRET

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError:
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError:
        return HttpResponse(status=400)

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_id = session.get('customer')

        # Buscar subscripción
        try:
            subscription = BusinessSubscription.objects.get(stripe_customer_id=customer_id)
            business = subscription.business
            if business:
                business.is_active = True
                business.save()
        except BusinessSubscription.DoesNotExist:
            pass

    return HttpResponse(status=200)

@login_required
def create_or_update_business(request, business_id=None):
    if business_id:
        business = get_object_or_404(Business, id=business_id)
        if business.owner != request.user:
            return HttpResponseForbidden("No estás autorizado para editar este negocio.")
    else:
        business = None

    user_giro = request.user.userprofile.giro_de_negocio

    if request.method == 'POST':
        form = BusinessForm(request.POST, request.FILES, instance=business)

        if form.is_valid():
            is_creating = business is None
            business_obj = form.save(commit=False)

            if is_creating:
                business_obj.owner = request.user
                business_obj.owner_or_manager_email = request.user.email
                business_obj.city = request.user.userprofile.city
                business_obj.tipos_de_negocio = user_giro
                business_obj.is_active = False  # Solo para nuevos negocios
            else:
                # IMPORTANTE: Al editar, preservar campos críticos
                original_business = Business.objects.get(id=business.id)
                business_obj.tipos_de_negocio = user_giro  # Forzar a usar el giro del usuario
                business_obj.is_active = original_business.is_active  # Preservar estado de activación
                business_obj.owner = original_business.owner  # Preservar propietario
                business_obj.city = original_business.city  # Preservar ciudad

            business_obj.save()

            if is_creating:
                return redirect('redirect_to_stripe_checkout', business_id=business_obj.id)
            else:
                return redirect('dashboard')

    else:
        initial = {}
        if not business_id:
            initial['tipos_de_negocio'] = user_giro
        else:
            # Para edición, mostrar el giro actual del usuario (no del negocio)
            initial['tipos_de_negocio'] = user_giro
            
        form = BusinessForm(instance=business, initial=initial)
        
        # Si estamos editando, deshabilitar el campo tipos_de_negocio
        if business_id:
            form.fields['tipos_de_negocio'].disabled = True
            form.fields['tipos_de_negocio'].help_text = "Este campo se basa en tu giro de negocio seleccionado en tu perfil y no puede ser modificado aquí."

    return render(request, 'business_form.html', {'form': form})

# ESTO LO ESTAMOS USANDO PARA LA SUSCRIPCION DEL NEGOCIO
@login_required
def redirect_to_stripe_checkout(request, business_id):
    try:
        business = get_object_or_404(Business, id=business_id, owner=request.user)

        num_businesses = Business.objects.filter(owner=request.user, is_active=True).count()
        price_id = settings.STRIPE_PRICE_FIRST_BUSINESS if num_businesses == 0 else settings.STRIPE_PRICE_ADDITIONAL_BUSINESS

        # El email del cliente para Stripe
        customer_email = request.user.email

        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            mode='subscription',
            customer_email=customer_email,  # <-- aquí el email
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            success_url=request.build_absolute_uri(reverse('subscription_success')) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.build_absolute_uri(reverse('subscription_cancelled', args=[business.id])),
            metadata={
                'business_id': str(business.id),
                'user_id': str(request.user.id),
            },
        )

        return render(request, 'redirect_to_stripe.html', {
            'session_id': checkout_session.id,
            'stripe_public_key': settings.STRIPE_PUBLISHABLE_KEY,
        })

    except Exception as e:
        print("ERROR en redirect_to_stripe_checkout:", str(e))
        return HttpResponse("Hubo un error al crear la sesión de pago.", status=500)

# ESTO LO ESTAMOS USANDO PARA LA SUSCRIPCION DEL NEGOCIO
@login_required
def subscription_success(request):
    session_id = request.GET.get('session_id')
    if not session_id or session_id == "{CHECKOUT_SESSION_ID}":
        return HttpResponseBadRequest("Sesión inválida o mal configurada")

    try:
        session = stripe.checkout.Session.retrieve(session_id)
    except stripe.error.InvalidRequestError:
        return HttpResponseBadRequest("No se pudo obtener la sesión de Stripe")

    subscription_id = session.subscription
    customer_id = session.customer
    business_id = session.metadata.get('business_id')

    try:
        business = Business.objects.get(id=business_id)
    except Business.DoesNotExist:
        return HttpResponse("Negocio no encontrado")

    if not BusinessSubscription.objects.filter(stripe_subscription_id=subscription_id).exists():
        BusinessSubscription.objects.create(
            user=request.user,
            stripe_subscription_id=subscription_id,
            stripe_customer_id=customer_id,
            business=business,
            is_active=True,
        )

        # Activar el negocio después de suscribirse
        business.is_active = True
        business.save()

    messages.success(request, "Suscripción exitosa. Tu negocio ya está activo.")
    return redirect('dashboard')

# ESTO LO ESTAMOS USANDO PARA LA SUSCRIPCION DEL NEGOCIO
@login_required
def subscription_cancelled(request, business_id):
    messages.info(request, "No completaste el pago de suscripción. Puedes intentarlo más tarde.")
    return redirect('dashboard')

### ESTA ES LA VISTA PARA MOSTRAR LOS DETALLES DEL NEGOCIO
@login_required
def business_detail(request, business_id):
    business = get_object_or_404(Business, id=business_id)

    # Intenta obtener el perfil del usuario (UserProfile o ConductorUser)
    try:
        profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        try:
            profile = request.user.conductoruser
        except ConductorUser.DoesNotExist:
            return redirect('not_authorized')

    # Permissions check
    if profile.role == 'business_owner' and business.owner != request.user:
        return redirect('not_authorized')
    elif profile.role == 'conductor' and business.city != profile.city:
        return redirect('not_authorized')

    # Si el perfil tiene `giro_de_negocio`, lo usamos, si no, lo dejamos como None
    tipo_de_negocio = getattr(profile, 'giro_de_negocio', None)

    # Get products
    productos = Producto.objects.filter(business=business)

    return render(request, 'detail_business.html', {
        'business': business,
        'productos': productos,
        'profile': profile,
        'tipo_de_negocio': tipo_de_negocio,
    })

def business_detail(request, business_id):
    business = get_object_or_404(Business, id=business_id)
    productos = Producto.objects.filter(business=business)

    return render(request, 'detail_business.html', {
        'business': business,
        'productos': productos,
        'profile': None,
        'tipo_de_negocio': None,
    })

##ESTA ES LA VISTA PARA ELIMINAR UN NEGOCIO    
@login_required
def eliminar_negocio(request, business_id):
    business = get_object_or_404(Business, id=business_id)

    # Only allow deletion if the logged-in user is the owner/manager
    if request.user.email != business.owner_or_manager_email:
        return redirect('not_authorized')

    if request.method == 'POST':
        business.delete()
        return redirect('dashboard')

    return render(request, 'confirm_delete.html', {'business': business})    

def send_email(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            company_name=form.cleaned_data['company_name']
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            phone = form.cleaned_data['phone']
            message = form.cleaned_data['message']

            # Process the form data, e.g., send an email
            send_mail(
                f'Contact Form Submission from {name}',
                f'Nombre de la Compañia: {company_name}\nMi Nombre: {name}\nPhone: {phone}\nEmail: {email}\n Descripcion de la empresa: {message}',
                'saborlocalpv@gmail.com',  # From email
                ['saborlocalpv@gmail.com'],  # To email
                fail_silently=False,
            )

            messages.success(request, 'Email enviado!  te responderemos lo mas pronto posible.')
            return redirect('index')
    else:
        form = ContactForm()

    return render(request, 'index.html', {'form': form})

##ESTO ES CUANDO EL USUARIO SE LOGUEO CON OTRA CUENTA Y YA EN LA OTRA PESTAÑA ACTUALIZA LO VA REDIRIGIR AQUI 
@login_required
def not_authorized(request):
    return render(request, 'navegador_expirado.html')

#ESTA ES LA VISTA PARA MOSTRAR EL PERFIL DEL USUARIO
@login_required
def view_profile(request):
    try:
        profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        try:
            profile = request.user.conductoruser
        except ConductorUser.DoesNotExist:
            return redirect('not_authorized')

    if profile.role == 'business_owner':
        template = 'view_profile_business_owner.html'
    elif profile.role == 'conductor':
        template = 'view_profile_concierge.html'
    else:
        return redirect('not_authorized')

    return render(request, template, {
        'user': request.user,
        'profile': profile
    })

#VISTA PARA EDITAR PERFIL DE USUARIO
@login_required
def edit_profile(request):
    user = request.user

    # Intenta obtener cualquiera de los dos perfiles
    try:
        profile = user.userprofile
    except UserProfile.DoesNotExist:
        try:
            profile = user.conductoruser
        except ConductorUser.DoesNotExist:
            return redirect('not_authorized')

    original_role = profile.role  # Bloquea el cambio de rol

    user_form = EditUserForm(request.POST or None, instance=user)

    # Elige el formulario correcto según el rol
    if original_role == 'business_owner':
        profile_form = EditBusinessOwnerProfileForm(
            request.POST or None, request.FILES or None, instance=profile
        )
    elif original_role == 'conductor':
        profile_form = EditarConductorProfile(  # ✅ CAMBIO AQUÍ
            request.POST or None, request.FILES or None, instance=profile
        )
    else:
        return redirect('not_authorized')

    if request.method == 'POST':
        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save(commit=False)
            password = user_form.cleaned_data.get("password")
            if password:
                user.set_password(password)
                update_session_auth_hash(request, user)
            user.save()

            updated_profile = profile_form.save(commit=False)
            updated_profile.role = original_role
            updated_profile.save()

            return redirect('view_profile')

    return render(request, 'editar_perfil_usuario.html', {
        'user_form': user_form,
        'profile_form': profile_form,
    })

def logout_user(request):
    logout(request)
    return redirect('index') 

##CAMBIAR LA CONTRASEÑA DE USUARIO
@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Keeps the user logged in
            messages.success(request, 'Tu contraseña se ha cambiado correctamente!')
            return redirect('index')
        else:
            messages.error(request, 'Porfavor corrige los siguientes errores.')
    else:
        form = PasswordChangeForm(user=request.user)
    return render(request, 'change_password.html',{'form': form})

#ESTA ES LA VISTA PARA AGREGAR UN PRODUCTO ESTANDAR A UN NEGOCIO
@login_required
def agregar_item_menu_negocio(request, business_id):
    business = get_object_or_404(Business, id=business_id, owner=request.user)

    if request.method == 'POST':
        form = ProductoForm(request.POST, request.FILES, business_instance=business)
        if form.is_valid():
            producto = form.save(commit=False)
            producto.business = business
            producto.tipo_subcategoria = business.tipos_de_negocio  # Asigna el tipo
            producto.save()
            return redirect('dashboard')  
    else:
        form = ProductoForm(business_instance=business)

    return render(request, 'agregar_producto.html', {'form': form, 'business': business})

@login_required
def agregar_extra(request, producto_id):
    producto = get_object_or_404(Producto, id=producto_id)

    if producto.business.owner != request.user:
        return HttpResponseForbidden("No tienes permiso para agregar extras a este producto.")

    if request.method == 'POST':
        form = ExtraForm(request.POST)
        if form.is_valid():
            extra = form.save(commit=False)
            extra.producto = producto
            extra.save()
            return redirect('agregar_extra', producto_id=producto.id)
    else:
        form = ExtraForm()

    extras = producto.extras.all()

    return render(request, 'agregar_extras.html', {
        'producto': producto,
        'form': form,
        'extras': extras,
        'editando': False,  # O simplemente omitirlo
    })

@login_required
def ver_extras_negocio(request, business_id):
    negocio = get_object_or_404(Business, id=business_id)

    # Verificar que el negocio pertenece al usuario actual
    if negocio.owner != request.user:
        return HttpResponseForbidden("No tienes permiso para ver estos extras.")

    # Obtener todos los productos del negocio con sus extras
    productos = Producto.objects.filter(business=negocio).prefetch_related('extra_set')

    return render(request, 'ver_extras_negocio.html', {
        'negocio': negocio,
        'productos': productos
    })

@login_required
def editar_extra(request, extra_id):
    extra = get_object_or_404(Extra, id=extra_id)
    producto = extra.producto

    # Verificar que el usuario sea el dueño del negocio
    if producto.business.owner != request.user:
        return HttpResponseForbidden("No tienes permiso para editar este extra.")

    if request.method == 'POST':
        form = ExtraForm(request.POST, instance=extra)
        if form.is_valid():
            form.save()
            return redirect('agregar_extra', producto_id=producto.id)
    else:
        form = ExtraForm(instance=extra)

    # Aquí pasamos editando=True y NO pasamos los extras
    return render(request, 'agregar_extras.html', {
        'producto': producto,
        'form': form,
        'editando': True,
    })

@login_required
def eliminar_extra(request, extra_id):
    extra = get_object_or_404(Extra, id=extra_id)

    # Verifica que el usuario actual sea el dueño del negocio al que pertenece el producto
    if extra.producto.business.owner != request.user:
        return HttpResponseForbidden("No tienes permiso para eliminar este extra.")

    business_id = extra.producto.business.id
    extra.delete()
    return redirect('menu', business_id=business_id)

#ESTA ES LA VISTA DONDE ESTOY MOSTRANDO LOS PRODUCTOS ESTANDAR , AQUI NO SE ESTAN MOSTRANDO LOS PRODUCTOS DE HOTELERIA
def ver_menu_negocio(request, business_id):
    business = get_object_or_404(Business, id=business_id)
    productos = Producto.objects.filter(business=business).prefetch_related('extras').order_by('name')

    return render(request, 'menu.html', {
        'business': business,
        'productos': productos
    })

#EDITAR PRODUCTO ESTANDAR 
@login_required
def editar_producto_menu(request, producto_id):
    producto = get_object_or_404(Producto, id=producto_id)
    profile = request.user.userprofile

    # Access control
    if profile.role == 'business_owner' and producto.business.owner != request.user:
        return redirect('not_authorized')
    elif profile.role == 'concierge' and producto.business.city != profile.city:
        return redirect('not_authorized')

    business = producto.business

    if request.method == 'POST':
        form = ProductoForm(request.POST, request.FILES, instance=producto)
        if form.is_valid():
            form.save()
            return redirect('dashboard')
    else:
        form = ProductoForm(instance=producto)

    return render(request, 'agregar_producto.html', {
        'form': form,
        'business': business,
        'editing': True,
        'producto': producto
    })

#ELIMINAR PRODUCTO ESTANDAR     
@login_required
def eliminar_producto_menu(request, producto_id):
    producto = get_object_or_404(Producto, id=producto_id)

    # Solo permite eliminar si el usuario es el propietario del producto
    if request.user.userprofile.role != 'business_owner':
        return redirect('not_authorized')

    if request.method == 'POST':
        producto.delete()
        return redirect('dashboard')

    return render(request, 'confirm_delete.html', {'producto': producto})

def get_or_create_cart(request):
    if not request.session.session_key:
        request.session.create()

    session_key = request.session.session_key

    cart, created = Cart.objects.get_or_create(session_key=session_key)
    request.session['cart_id'] = cart.id  # Por si quieres seguir usándolo
    return cart

def add_to_cart(request, producto_id):
    producto = get_object_or_404(Producto, id=producto_id)
    cart = get_or_create_cart(request)

    if cart.items.exists():
        negocio_existente = cart.items.first().producto.business
        if producto.business != negocio_existente:
            return JsonResponse({
                "status": "error",
                "message": "Tu carrito ya contiene productos de otro negocio. Finaliza esa compra antes de agregar productos de un nuevo negocio."
            })

    # 📦 Cantidad del producto
    cantidad_str = request.POST.get("cantidad", "1")
    cantidad = int(cantidad_str) if cantidad_str.isdigit() else 1

    # 📝 Nota personalizada
    nota = request.POST.get("nota", "").strip()

    # ➕ Crea el item con cantidad y nota
    item = CartItem.objects.create(cart=cart, producto=producto, cantidad=cantidad, nota=nota)

    # 🎯 Procesa extras con nombre extra_ID = cantidad
    for key in request.POST:
        if key.startswith("extra_"):
            extra_id = key.split("_")[1]
            cantidad_extra_str = request.POST[key]
            if cantidad_extra_str and cantidad_extra_str.isdigit():
                cantidad_extra = int(cantidad_extra_str)
                if cantidad_extra > 0:
                    try:
                        extra = Extra.objects.get(id=extra_id)
                        ExtraEnCarrito.objects.create(cart_item=item, extra=extra, cantidad=cantidad_extra)
                    except Extra.DoesNotExist:
                        continue

    return JsonResponse({
        "status": "success",
        "message": f"Agregado {producto.name} al carrito."
    })

###ver carrito
def ver_carrito(request):
    cart = get_or_create_cart(request)

    # Procesa solo si viene del botón "guardar" o "proceder"
    if request.method == "POST":
        action = request.POST.get('action')

        if action in ['guardar', 'proceder']:
            for item in cart.items.all():
                # 🔄 Actualiza la cantidad del producto
                cantidad_str = request.POST.get(f'cantidad_{item.id}')
                if cantidad_str and cantidad_str.isdigit():
                    cantidad = int(cantidad_str)
                    if cantidad > 0:
                        item.cantidad = cantidad

                # 📝 Actualiza la nota del producto
                nota = request.POST.get(f'nota_{item.id}', '').strip()
                item.nota = nota  # 👈 Guarda la nota escrita por el usuario

                item.save()

                # 🔁 Elimina los extras anteriores del carrito
                item.extras_en_carrito.all().delete()

                # ➕ Agrega extras nuevos desde el POST
                for key in request.POST:
                    if key.startswith(f'extra_{item.id}_'):
                        extra_id = key.split('_')[-1]
                        cantidad_str = request.POST[key]
                        if cantidad_str and cantidad_str.isdigit():
                            cantidad = int(cantidad_str)
                            if cantidad > 0:
                                try:
                                    extra = Extra.objects.get(id=extra_id)
                                    ExtraEnCarrito.objects.create(
                                        cart_item=item,
                                        extra=extra,
                                        cantidad=cantidad
                                    )
                                except Extra.DoesNotExist:
                                    continue  # Ignora si el extra no existe

            if action == 'proceder':
                return redirect('direccion_envio')

    # 🧮 Cálculo de subtotales por producto y total general
    cart_items_info = []
    total_general = 0

    for item in cart.items.all():
        subtotal_producto = item.producto.price * item.cantidad

        extras_info = []
        subtotal_extras = 0
        for extra_item in item.extras_en_carrito.all():
            subtotal_extra = extra_item.extra.precio * extra_item.cantidad
            extras_info.append({
                'nombre': extra_item.extra.nombre,
                'cantidad': extra_item.cantidad,
                'precio': extra_item.extra.precio,
                'subtotal': subtotal_extra
            })
            subtotal_extras += subtotal_extra

        subtotal_total = subtotal_producto + subtotal_extras
        total_general += subtotal_total

        cart_items_info.append({
            'item': item,
            'nota': item.nota,
            'subtotal_producto': subtotal_producto,
            'extras_info': extras_info,
            'subtotal_extras': subtotal_extras,
            'subtotal_total': subtotal_total
        })

    # ✅ Detectar si el carrito está vacío
    carrito_vacio = not cart.items.exists()

    return render(request, 'carrito.html', {
        'cart': cart,
        'cart_items_info': cart_items_info,
        'total_general': total_general,
        'carrito_vacio': carrito_vacio,  # 👈 Se pasa al template
    })

@require_http_methods(["GET", "POST"])  # Permite GET además de POST
def eliminar_item_carrito(request, item_id):
    print(f"Intentando eliminar item_id: {item_id}")  # Debug

    cart = get_or_create_cart(request)
    try:
        item = CartItem.objects.get(id=item_id, cart=cart)
        item.delete()
        print(f"Item {item_id} eliminado correctamente")
    except CartItem.DoesNotExist:
        print(f"Item {item_id} no existe o no pertenece al carrito")

    return redirect('ver_carrito')

# ESTA VISTA LA CREE PARA QUE SE PUEDAN ACTUALIZAR CON AJAX AUTOMATICAAMENTE LAS CANTIDADES Y EXTRAS DEL CARRITO
@csrf_exempt
def actualizar_carrito_ajax(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        item_id = data.get('item_id')
        cantidad = data.get('cantidad')
        extras = data.get('extras', {})
        nota = data.get('nota', '')  # <-- obtener la nota

        try:
            item = CartItem.objects.get(id=item_id)
            if cantidad and int(cantidad) > 0:
                item.cantidad = int(cantidad)

            item.nota = nota  # <-- guardar nota
            item.save()

            item.extras_en_carrito.all().delete()
            for extra_id_str, cantidad_str in extras.items():
                if cantidad_str and cantidad_str.isdigit() and int(cantidad_str) > 0:
                    extra = Extra.objects.get(id=int(extra_id_str))
                    ExtraEnCarrito.objects.create(cart_item=item, extra=extra, cantidad=int(cantidad_str))

            # Calcular total
            cart = item.cart
            total_general = 0
            for cart_item in cart.items.all():
                subtotal_producto = cart_item.producto.price * cart_item.cantidad
                subtotal_extras = sum(
                    e.extra.precio * e.cantidad for e in cart_item.extras_en_carrito.all()
                )
                total_general += subtotal_producto + subtotal_extras

            return JsonResponse({
                'status': 'success',
                'total_general': total_general
            })

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    return JsonResponse({'status': 'error', 'message': 'Método no permitido'}, status=405)

# VISTA ACTUALIZADA PARA HOTEL - direccion_envio
def direccion_envio(request):
    cart = get_or_create_cart(request)

    # Calcula subtotal de productos y subtotal de extras (SIN envío ni propina)
    subtotal_productos = Decimal('0.00')
    subtotal_extras = Decimal('0.00')
    for item in cart.items.all():
        subtotal_productos += Decimal(item.producto.price) * item.cantidad
        for extra_item in item.extras_en_carrito.all():
            precio_extra = Decimal(extra_item.extra.precio or 0)
            subtotal_extras += precio_extra * extra_item.cantidad

    subtotal_total = subtotal_productos + subtotal_extras

    # Obtener el negocio del carrito
    negocio = None
    if cart.items.exists():
        negocio = cart.items.first().producto.business

    # Definir los métodos de pago disponibles según el negocio
    metodos_pago_disponibles = []

    if negocio:
        if negocio.acepta_tarjeta:
            metodos_pago_disponibles.append(('tarjeta', 'Tarjeta de crédito/débito'))
        if negocio.acepta_efectivo:
            metodos_pago_disponibles.append(('efectivo', 'Efectivo al recibir'))
        
        # NUEVA OPCIÓN: Cargo a habitación (siempre disponible para hoteles)
        metodos_pago_disponibles.append(('habitacion', 'Cargo a habitación'))

    # NUEVO: Opciones de entrega para hotel (siempre ambas disponibles)
    opciones_entrega = [
        ('roomservice', 'Room Service - Entrega en habitación'),
        ('restaurante', 'Bajar al restaurante'),
    ]

    if request.method == "POST":
        print("POST recibido en direccion_envio")
        print(f"Datos POST: {request.POST}")
        
        # Agregar costo_envio = 0 (siempre para hotel)
        data = request.POST.copy()
        data['costo_envio'] = 0
        
        form = DireccionDeEnvioForm(data, opciones_entrega=opciones_entrega)
        metodo_pago = request.POST.get('metodo_pago')
        print(f"Método de pago: {metodo_pago}")

        # Validar que el método de pago seleccionado esté permitido
        if metodo_pago not in [m[0] for m in metodos_pago_disponibles]:
            print("Método de pago no válido")
            return HttpResponseBadRequest("El método de pago seleccionado no está disponible para este negocio.")

        if form.is_valid():
            print("Form válido, procesando...")
            
            direccion_envio = form.save(commit=False)
            
            # SIEMPRE costo de envío = 0 para hotel
            direccion_envio.costo_envio = 0
            
            # Limpiar campos no necesarios para hotel
            direccion_envio.direccion = ''
            direccion_envio.ciudad = ''
            direccion_envio.estado = ''
            direccion_envio.codigo_postal = ''
            direccion_envio.latitude = None
            direccion_envio.longitude = None

            # 🔹 NUEVO: si opción_entrega es restaurante -> decidir_propina_despues = True
            opcion_entrega = form.cleaned_data.get('opcion_entrega')
            if opcion_entrega == "restaurante":
                direccion_envio.decidir_propina_despues = True

            # Si el usuario marcó decidir_propina_despues o lo forzamos arriba
            if direccion_envio.decidir_propina_despues:
                direccion_envio.propina_voluntaria = 0

            print("Guardando información de hotel...")
            direccion_envio.save()
            request.session['direccion_envio_id'] = direccion_envio.id
            request.session['metodo_pago'] = metodo_pago
            print(f"Guardado con ID: {direccion_envio.id}")

            # LÓGICA DE REDIRECCIÓN ACTUALIZADA
            if metodo_pago in ['efectivo', 'habitacion']:  # AMBOS van directo a success
                print(f"Redirigiendo a success ({metodo_pago})")
                return redirect('success')
            else:
                print("Redirigiendo a checkout (tarjeta)")
                return redirect('checkout')
        else:
            print("Form NO válido:")
            print(f"Errores: {form.errors}")
            for field, errors in form.errors.items():
                print(f"Campo {field}: {errors}")
    else:
        form = DireccionDeEnvioForm(opciones_entrega=opciones_entrega)

    return render(request, 'direccion_envio.html', {
        'form': form,
        'subtotal_productos': subtotal_productos,
        'subtotal_extras': subtotal_extras,
        'subtotal_total': subtotal_total,
        'metodos_pago_disponibles': metodos_pago_disponibles,
        'negocio_nombre': negocio.commercial_name if negocio else '',
    })


# VISTA ACTUALIZADA PARA HOTEL - checkout
def checkout(request):
    import stripe

    cart = get_or_create_cart(request)
    direccion_envio_id = request.session.get('direccion_envio_id')
    direccion_envio = None
    if direccion_envio_id:
        try:
            direccion_envio = DireccionDeEnvio.objects.get(id=direccion_envio_id)
        except DireccionDeEnvio.DoesNotExist:
            pass

    metodo_pago = request.POST.get('metodo_pago', 'tarjeta')

    line_items = []
    negocio = None

    for item in cart.items.all():
        negocio = item.producto.business
        line_items.append({
            'price_data': {
                'currency': 'mxn',
                'product_data': {'name': item.producto.name},
                'unit_amount': int(item.producto.price * 100),
            },
            'quantity': item.cantidad,
        })
        for extra_item in item.extras_en_carrito.all():
            precio_extra = extra_item.extra.precio or 0
            line_items.append({
                'price_data': {
                    'currency': 'mxn',
                    'product_data': {
                        'name': f"{extra_item.extra.nombre} (Extra de {item.producto.name})"
                    },
                    'unit_amount': int(precio_extra * 100),
                },
                'quantity': extra_item.cantidad,
            })

    # NO HAY COSTO DE ENVÍO EN HOTEL - líneas removidas
    
    # Agregar propina si existe
    if direccion_envio and direccion_envio.propina_voluntaria and direccion_envio.propina_voluntaria > 0:
        line_items.append({
            'price_data': {
                'currency': 'mxn',
                'product_data': {'name': 'Propina'},
                'unit_amount': int(direccion_envio.propina_voluntaria * 100),
            },
            'quantity': 1,
        })

    total_pagado = sum(item['price_data']['unit_amount'] * item['quantity'] for item in line_items) / 100

    # LÓGICA ACTUALIZADA PARA EFECTIVO Y CARGO A HABITACIÓN
    if metodo_pago in ['efectivo', 'habitacion']:
        pedido = Pedido.objects.create(
            cliente=request.user if request.user.is_authenticated else None,
            direccion_envio=direccion_envio,
            total_pagado=total_pagado,
            session_key=request.session.session_key,
            metodo_pago=metodo_pago,
            pagado=True  # Ambos métodos se marcan como pagados
        )
        cart.items.all().delete()
        return redirect('/carrito/success/')

    # Solo para tarjeta - proceso Stripe normal
    if negocio and negocio.owner.userprofile.stripe_secret_key:
        stripe.api_key = negocio.owner.userprofile.stripe_secret_key

        email_para_checkout = request.user.email if request.user.is_authenticated else 'saborlocalpv@gmail.com'

        stripe_params = {
            'payment_method_types': ['card'],
            'line_items': line_items,
            'mode': 'payment',
            'success_url': request.build_absolute_uri('/carrito/success/'),
            'cancel_url': request.build_absolute_uri('/carrito/cancel/'),
            'customer_email': email_para_checkout,
        }

        if direccion_envio:
            stripe_params['metadata'] = {
                'metodo_entrega': direccion_envio.opcion_entrega,
                'nombre_completo': direccion_envio.nombre_completo,
                'telefono': direccion_envio.telefono,
                'numero_habitacion': direccion_envio.numero_habitacion or '',
                'metodo_pago': 'tarjeta',
            }

        checkout_session = stripe.checkout.Session.create(**stripe_params)
        return redirect(checkout_session.url)

    else:
        return HttpResponse("Este negocio no tiene clave secreta Stripe registrada.")

# VISTA ACTUALIZADA PARA HOTEL - success
def success(request):
    cart = get_or_create_cart(request)
    direccion_id = request.session.get('direccion_envio_id')
    direccion_envio = DireccionDeEnvio.objects.filter(id=direccion_id).first()
    user = request.user if request.user.is_authenticated else None

    pedido = None
    metodo_pago = request.session.get('metodo_pago', 'tarjeta')

    if cart and cart.items.exists():
        pedido = Pedido.objects.create(
            cliente=user,
            direccion_envio=direccion_envio,
            pagado=True,
            session_key=cart.session_key if hasattr(cart, 'session_key') else None,
            metodo_pago=metodo_pago,
        )

        for item in cart.items.all():
            venta = Venta.objects.create(
                pedido=pedido,
                business=item.producto.business,
                producto=item.producto,
                cantidad=item.cantidad,
                precio_unitario=item.producto.price,
                subtotal=item.subtotal(),
                direccion_envio=direccion_envio,
                cliente=user,
                pagado=True,
                nota=item.nota
            )

            for extra_carrito in item.extras_en_carrito.all():
                ExtraEnVenta.objects.create(
                    venta=venta,
                    extra=extra_carrito.extra,
                    cantidad=extra_carrito.cantidad,
                )

        cart.delete()
        request.session.pop('cart_id', None)
        request.session.pop('direccion_envio_id', None)
        request.session.pop('metodo_pago', None)

    pedido_data = {}
    if pedido:
        ventas_del_pedido = Venta.objects.filter(pedido=pedido).select_related(
            'producto', 'cliente', 'pedido', 'direccion_envio', 'business'
        ).prefetch_related('extras_en_venta__extra')

        d = pedido.direccion_envio
        direccion_data = None
        whatsapp = ""

        if d:
            # DATOS ACTUALIZADOS PARA HOTEL
            direccion_data = {
                'fecha_creacion': d.fecha_creacion,
                'nombre_completo': d.nombre_completo,
                'telefono': d.telefono,
                'opcion_entrega': d.opcion_entrega,
                'opcion_entrega_display': d.get_opcion_entrega_display(),
                'numero_habitacion': d.numero_habitacion,
                'propina_voluntaria': d.propina_voluntaria,
                'decidir_propina_despues': d.decidir_propina_despues,
                'notas': d.notas,
            }
            whatsapp = d.telefono

        ventas_info = []
        total_pedido = Decimal('0.00')

        for venta in ventas_del_pedido:
            extras_info = []
            for extra_rel in venta.extras_en_venta.all():
                extra = extra_rel.extra
                cantidad = extra_rel.cantidad
                subtotal_extra = extra.precio * cantidad
                extras_info.append({
                    'nombre': extra.nombre,
                    'precio': extra.precio,
                    'cantidad': cantidad,
                    'subtotal': subtotal_extra,
                })

            venta_subtotal = venta.subtotal
            total_pedido += venta_subtotal

            ventas_info.append({
                'producto': venta.producto.name,
                'imagen': venta.producto.image1.url if venta.producto.image1 else None,
                'cantidad': venta.cantidad,
                'precio_unitario': venta.precio_unitario,
                'subtotal': venta_subtotal,
                'extras': extras_info or None,
                'negocio': venta.business.commercial_name,
                'nota': venta.nota,
            })

        # SIN COSTO DE ENVÍO EN HOTEL
        costo_envio = Decimal('0.00')

        # Agregar propina al total
        if d:
            total_pedido += d.propina_voluntaria or 0

        pedido_data = {
            'pedido': pedido,
            'direccion': direccion_data,
            'ventas': ventas_info,
            'total_pagado': total_pedido,
            'costo_envio': costo_envio,
            'whatsapp': whatsapp,
            'metodo_pago': metodo_pago,
        }

    return render(request, 'success.html', {
        'pedido': pedido_data,
        'metodo_pago': metodo_pago,
    })

# VISTA ACTUALIZADA PARA HOTEL - ver_pedidos_por_negocio
@login_required
def ver_pedidos_por_negocio(request, business_id):
    business = get_object_or_404(Business, id=business_id, owner=request.user)

    ventas = Venta.objects.filter(business=business).exclude(pedido=None).select_related(
        'producto', 'cliente', 'pedido', 'direccion_envio'
    ).prefetch_related('extras_en_venta__extra')

    pedidos_dict = defaultdict(list)
    for venta in ventas:
        pedidos_dict[venta.pedido].append(venta)

    pedidos_pendientes = []
    pedidos_enviados = []

    for pedido, ventas_del_pedido in pedidos_dict.items():
        d = pedido.direccion_envio
        direccion_data = None
        whatsapp = ""

        if d:
            # DATOS ACTUALIZADOS PARA HOTEL
            direccion_data = {
                'fecha_creacion': d.fecha_creacion,
                'nombre_completo': d.nombre_completo,
                'telefono': d.telefono,
                'opcion_entrega': d.get_opcion_entrega_display(),
                'numero_habitacion': d.numero_habitacion,
                
                'propina_voluntaria': d.propina_voluntaria,
                'notas': d.notas,
            }
            whatsapp = d.telefono

        ventas_info = []
        total_pedido = Decimal('0.00')

        for venta in ventas_del_pedido:
            extras_info = []
            for extra_rel in venta.extras_en_venta.all():
                extra = extra_rel.extra
                cantidad = extra_rel.cantidad
                subtotal_extra = extra.precio * cantidad
                extras_info.append({
                    'nombre': extra.nombre,
                    'precio': extra.precio,
                    'cantidad': cantidad,
                    'subtotal': subtotal_extra,
                })

            venta_subtotal = venta.subtotal
            total_pedido += venta_subtotal

            ventas_info.append({
                'producto': venta.producto.name,
                'cantidad': venta.cantidad,
                'precio_unitario': venta.precio_unitario,
                'subtotal': venta_subtotal,
                'extras': extras_info or None,
                'negocio': venta.business.commercial_name,
                'nota': venta.nota,
            })

        # SIN COSTO DE ENVÍO EN HOTEL
        costo_envio = Decimal('0.00')

        # Propina
        if d:
            total_pedido += d.propina_voluntaria or 0

        pedido_data = {
            'pedido': pedido,
            'direccion': direccion_data,
            'ventas': ventas_info,
            'total_pagado': total_pedido,
            'costo_envio': costo_envio,
            'whatsapp': whatsapp,
            'metodo_pago': pedido.metodo_pago,
        }

        if pedido.enviado:
            pedidos_enviados.append(pedido_data)
        else:
            pedidos_pendientes.append(pedido_data)

    return render(request, 'ver_pedidos.html', {
        'business': business,
        'pedidos_pendientes': pedidos_pendientes,
        'pedidos_enviados': pedidos_enviados,
    })

@require_POST
@login_required
def marcar_envio_pedido(request, pedido_id):
    pedido = get_object_or_404(Pedido, id=pedido_id)
    
    # Verificar que el usuario es dueño del negocio al que pertenece al menos una venta del pedido
    if not pedido.ventas.filter(business__owner=request.user).exists():
        return HttpResponseForbidden("No tienes permiso para modificar este pedido.")

    pedido.enviado = 'enviado' in request.POST
    pedido.save()
    return redirect(request.META.get('HTTP_REFERER', '/'))

#ESTA VISTA LA CREE PARA QUE LA PLANTILLA DE PEDIDOS SE ACTUALICE AUTOMATICAMENTE Y A LA VEZ QUE EMITA UN SONIDO CADA QUE DETECTE UN NUEVO PEDIDO
@login_required
def obtener_pedidos_pendientes(request, business_id):
    pedidos = Pedido.objects.filter(
        enviado=False,
        ventas__business__id=business_id,
        ventas__business__owner=request.user
    ).distinct()

    ids = list(pedidos.values_list('id', flat=True))
    return JsonResponse({'ids': ids})

def terminos_y_condiciones(request):
    return render(request, 'terminos_y_condiciones.html')

def politica_de_privacidad(request):
    return render(request, 'politica_de_privacidad.html')




# instalar  :   pip install qrcode[pil]

import qrcode
import base64
from io import BytesIO
from django.shortcuts import render
import random
from PIL import Image, ImageDraw, ImageFont
import os

def generar_qr(request):
    qr_personalizado = None
    qr_variantes = []

    # Valores por defecto
    numero = ""
    mensaje = ""
    url = ""
    tipo_qr = "whatsapp"
    color1 = "#000000"
    color2 = "#000000"
    color3 = "#000000"
    fondo = "#ffffff"
    text_color = "#000000"
    icono_file = None

    if request.method == "POST":
        numero = request.POST.get("numero", "")
        mensaje = request.POST.get("mensaje", "")
        url = request.POST.get("url", "")
        tipo_qr = request.POST.get("tipo_qr", "whatsapp")
        color1 = request.POST.get("color1", "#000000")
        color2 = request.POST.get("color2", "#000000")
        color3 = request.POST.get("color3", "#000000")
        fondo = request.POST.get("fondo", "#ffffff")
        text_color = request.POST.get("text_color", "#000000")
        accion = request.POST.get("accion")
        icono_file = request.FILES.get("icono")

        # Construir enlace sin incluir el mensaje
        if tipo_qr == "whatsapp" and numero:
            enlace = f"https://wa.me/{numero}"
        elif tipo_qr == "web" and url:
            enlace = url
        else:
            enlace = ""

        # Función para agregar ícono central
        def agregar_cuadro_con_icono(qr_img, icono=None, tamaño_icono=100):
            qr = qr_img.convert("RGBA")
            ancho, alto = qr.size
            x0 = (ancho - tamaño_icono) // 2
            y0 = (alto - tamaño_icono) // 2
            if icono:
                icono = icono.convert("RGBA")
                icono = icono.resize((tamaño_icono, tamaño_icono))
                qr.paste(icono, (x0, y0), icono)
            return qr

        # Función corregida para generar QR con gradiente de 3 colores
        def generar_qr_img(colors, back):
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=4,
            )
            qr.add_data(enlace)
            qr.make(fit=True)
            
            # Convertir colores hex a tupla RGBA con validación
            def hex_to_rgba(hex_color):
                # Validar y limpiar el color hex
                if not hex_color or not isinstance(hex_color, str):
                    hex_color = "#000000"
                
                hex_color = hex_color.strip()
                if not hex_color.startswith("#"):
                    hex_color = "#" + hex_color
                
                # Remover el # y validar longitud
                hex_clean = hex_color.lstrip("#")
                if len(hex_clean) != 6:
                    hex_clean = "000000"  # Default a negro
                
                # Validar que todos los caracteres sean hexadecimales
                try:
                    return tuple(int(hex_clean[i:i+2], 16) for i in (0, 2, 4)) + (255,)
                except ValueError:
                    return (0, 0, 0, 255)  # Default a negro si hay error

            # Convertir color de fondo
            back_color = hex_to_rgba(back)
            
            # Generar QR base con fondo blanco temporal
            img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
            
            ancho, alto = img.size
            grad = Image.new("RGBA", img.size, back_color)  # Inicializar con color de fondo

            c0 = hex_to_rgba(colors[0])
            c1 = hex_to_rgba(colors[1])
            c2 = hex_to_rgba(colors[2])

            # Aplicar gradiente solo en los módulos oscuros del QR
            for y in range(alto):
                ratio = y / alto
                if ratio < 0.5:
                    ratio2 = ratio * 2
                    c = tuple(int(c0[i]*(1-ratio2) + c1[i]*ratio2) for i in range(4))
                else:
                    ratio2 = (ratio - 0.5) * 2
                    c = tuple(int(c1[i]*(1-ratio2) + c2[i]*ratio2) for i in range(4))
                
                for x in range(ancho):
                    pixel = img.getpixel((x, y))
                    # Si el pixel es oscuro (parte del QR), aplicar gradiente
                    if pixel[0] < 128:  # Módulo oscuro del QR
                        grad.putpixel((x, y), c)
                    # Si es claro, mantener el color de fondo (ya está establecido)

            img = grad

            if icono_file:
                icono = Image.open(icono_file)
                img = agregar_cuadro_con_icono(img, icono)
            return img

        def img_to_base64(img):
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            return base64.b64encode(buffer.getvalue()).decode("utf-8")

        if accion == "generar" and enlace:
            img = generar_qr_img([color1, color2, color3], fondo)
            qr_personalizado = img_to_base64(img)

        elif accion == "otros" and enlace:
            # Obtener QRs existentes del POST
            qr_variantes_post = request.POST.getlist("qr_variantes_base64[]")
            qr_variantes = [{"qr": q} for q in qr_variantes_post]
            
            # Generar nuevos QRs aleatorios
            nuevos_qr = []
            for _ in range(4):
                fill_colors = ["#{:06x}".format(random.randint(0,0xFFFFFF)) for _ in range(3)]
                back = "#{:06x}".format(random.randint(0,0xFFFFFF))
                img = generar_qr_img(fill_colors, back)
                nuevos_qr.append({"qr": img_to_base64(img)})
            
            # Agregar nuevos QRs al principio de la lista
            qr_variantes = nuevos_qr + qr_variantes

    return render(request, "generar_qr.html", {
        "qr_personalizado": qr_personalizado,
        "qr_variantes": qr_variantes,
        "numero": numero,
        "mensaje": mensaje,  # solo para mostrar debajo del QR
        "url": url,
        "tipo_qr": tipo_qr,
        "color1": color1,
        "color2": color2,
        "color3": color3,
        "fondo": fondo,
        "text_color": text_color,
    })



