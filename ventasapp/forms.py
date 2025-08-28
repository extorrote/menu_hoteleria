from .models import Business,Producto,UserProfile,CATEGORY_TYPES, CITIES,DAYS_OF_WEEK,ConductorUser,Extra
from django import forms
from datetime import datetime, timedelta 
from django.core.validators import RegexValidator
from django.contrib.auth.models import User
from ventasapp.labels import labels 


def generate_time_choices(step_minutes=30):
    from datetime import timedelta
    times = []
    current = datetime(2000, 1, 1, 0, 0)
    end = datetime(2000, 1, 2, 0, 0)
    while current <= end:
        value = current.strftime('%H:%M:%S')              
        label = current.strftime('%I:%M %p').lstrip('0')   
        times.append((value, label))
        current += timedelta(minutes=step_minutes)
    return times


def get_grouped_category_choices():
    grouped = []
    for categoria, opciones in CATEGORY_TYPES.items():
        label = categoria.replace('_', ' ').capitalize()
        grouped.append((label, opciones))
    return grouped



class BusinessForm(forms.ModelForm):
    
    tipos_de_negocio = forms.ChoiceField(
    required=False,
    widget=forms.Select,  #AQUI ESTA EL SELECT
    choices=get_grouped_category_choices(),
    label="Tipos de negocio"
    )

    closed_days = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple,
        choices=DAYS_OF_WEEK,
        label="Días cerrados",
        help_text="Selecciona los días en los que el negocio está cerrado."
    )

    opening_time = forms.ChoiceField(
        choices=generate_time_choices(),
        label="Hora de apertura"
    )
    closing_time = forms.ChoiceField(
        choices=generate_time_choices(),
        label="Hora de cierre"
    )

    class Meta:
        model = Business
        exclude = ['owner','city']  # ❗ Prevent manual assignment of the owner in the form
        labels = {
            'commercial_name': 'Nombre comercial',
            'time_category': 'Horario principal',
            'manager_name': 'Nombre del gerente o responsable',
            'owner_or_manager_whatsapp': 'WhatsApp del gerente o dueño',
            'owner_or_manager_email': 'Correo del gerente o dueño',
            'reservations_contact_name': 'Nombre para contacto de reservaciones',
            'reservations_whatsapp': 'WhatsApp para reservaciones',
            'reservations_email': 'Correo para reservaciones',
            'current_promotions': 'Promociones actuales',
            'image1': 'Imagen destacada 1',
            'image2': 'Imagen destacada 2',
            'image3': 'Imagen destacada 3',
            'image4': 'Imagen destacada 4',
            'address': 'Dirección del negocio',
            'website': 'Sitio web (opcional)',
            'stripe_id':'Stripe ID',
            'google_maps':'Locación en Google Maps',
            'description': 'Descripción detallada del negocio',
            
        }
        widgets = {
                'commissions': forms.NumberInput(attrs={
                'placeholder': ' Solo Números'
            })
            }

    def __init__(self, *args, **kwargs):
        super(BusinessForm, self).__init__(*args, **kwargs)
        self.fields['owner_or_manager_whatsapp'].widget.attrs.update({
            'placeholder': ' No espacios, Ej: +525581154023'
        })
        self.fields['reservations_whatsapp'].widget.attrs.update({
            'placeholder': ' No espacios, Ej: +525581154023'
        })
        

        # Pre-fill tipos_de_negocio from stored CSV string
        if self.instance and self.instance.tipos_de_negocio:
            self.initial['tipos_de_negocio'] = self.instance.tipos_de_negocio.split(',')

        # Pre-fill closed_days from stored CSV string
        if self.instance and self.instance.closed_days:
            self.initial['closed_days'] = self.instance.closed_days.split(',')

        # Pre-fill opening and closing times
        if self.instance and self.instance.opening_time:
            self.initial['opening_time'] = self.instance.opening_time.strftime('%H:%M:%S')
        if self.instance and self.instance.closing_time:
            self.initial['closing_time'] = self.instance.closing_time.strftime('%H:%M:%S')
            
    def clean_tipos_de_negocio(self):
        return self.cleaned_data.get('tipos_de_negocio', '')

    def clean_closed_days(self):
        data = self.cleaned_data.get('closed_days', [])
        return ','.join(data)

    def clean_opening_time(self):
        value = self.cleaned_data['opening_time']
        return datetime.strptime(value, '%H:%M:%S').time()

    def clean_closing_time(self):
        value = self.cleaned_data['closing_time']
        return datetime.strptime(value, '%H:%M:%S').time()








class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput,#######ESTE ES PARA LA MERA CONTRASEÑA
        label="Contraseña"
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput,#############ESTE ES PARA LA CONFIRMACION DE LA CONTRASEÑA
        label="Confirmar Contraseña"
    )

    class Meta:
        model = User
        fields = ['username', 'email','first_name','last_name' ,'password']
        labels = {
            'username': 'Nombre de usuario (con este iniciaras sesión)',#######AQUI ESTOY LLAMANDO DEL MODELO USER LA CONTRASEÑA EMAIL Y USERNAME
            'password': 'Contraseña',
             'first_name':'Tu Nombre',
            'last_name':'Apellidos',
            'email':'Correo Electronico',
        }

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get('password') != cleaned_data.get('confirm_password'):
            raise forms.ValidationError("Las contraseñas no coinciden.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])  # Hash the password
        user.email = self.cleaned_data["email"]  # Ensure email is set
        if commit:
            user.save()
        return user


########ESTOS SON PARA REGISTRAR AL USUARIO
class BusinessOwnerProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile##AQUI PARA QUE SE REGISTRE UN DUEÑO DE NEGOCIO ESTAMOS PIDIENDO ESTOS DATOS
        fields = ['city','company_name', 'giro_de_negocio','telephone','profile_picture', 'role','stripe_secret_key']
        labels = {
            
            'city': 'Ciudad',
            'company_name':'Nombre de tu Negocio',
            'telephone':'Numero de Telefono',
            'profile_picture': 'Foto de perfil',
            'giro_de_negocio':'Giro de Negocio'
        }
        widgets = {'role': forms.HiddenInput(),#ESTE LO ESTAMOS OCULTANDO PORQUE YA DESDE QUE ENTRA YA ENTRA AL METODO DE REGISTRO DE PROPIETARIO ENTONCES NO ES NECESARIO QUE ELIJA EL ROL DE NUEVO
        'profile_picture': forms.FileInput(attrs={'class': 'foto-perfil'})
        }
        


class ConductorProfileForm(forms.ModelForm):
        class Meta:
            model=ConductorUser
            fields = [
            'fecha_nacimiento', 'nacionalidad', 'curp', 'telefono', 'direccion', 'city', 'estado',
            'codigo_postal', 'licencia_numero', 'licencia_fecha_emision', 'licencia_fecha_vencimiento',
            'licencia_tipo', 'identificacion_oficial', 'comprobante_domicilio', 'tipo_vehiculo',
            'marca_vehiculo', 'modelo_vehiculo', 'anio_vehiculo', 'placas', 'color_vehiculo',
            'tarjeta_circulacion', 'seguro_vehiculo', 'cuenta_bancaria', 'clabe', 'banco',
            'titular_cuenta', 'zonas_operacion', 'dias_disponibles', 'horarios_disponibles',
            'antecedentes_penales', 'foto_selfie', 'firma_digital'
        ]
            labels= labels
        
        
        

############## ESTO PARA EDITAR LOS DATOS DE USUARIO DEL MODELO User      
class EditUserForm(forms.ModelForm):
    password = forms.CharField(
        label="Nueva contraseña",
        widget=forms.PasswordInput,
        required=False,
    )
    password_confirm = forms.CharField(
        label="Confirmar nueva contraseña",
        widget=forms.PasswordInput,
        required=False,
    )

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name']
        labels = {
            'first_name': 'Nombre',
            'last_name': 'Apellidos',
            'email': 'Correo electrónico',
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")

        if password or password_confirm:
            if password != password_confirm:
                self.add_error("password_confirm", "Las contraseñas no coinciden.")
        return cleaned_data

###ESTE PARA EDITAR LOS CAMPOS DEL MODELO DE UserProfile
class EditBusinessOwnerProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = [ 'company_name','telephone','profile_picture']
        widgets = {'role': forms.HiddenInput()}
        labels = {
            'profile_picture': 'Foto de perfil',
            'company_name':"Nombre de Compañia",
            
        }
        


class EditarConductorProfile(forms.ModelForm):
    class Meta:
        model = ConductorUser
        fields = [
            'fecha_nacimiento', 'nacionalidad', 'curp', 'telefono', 'direccion', 'city', 'estado',
            'codigo_postal', 'licencia_numero', 'licencia_fecha_emision', 'licencia_fecha_vencimiento',
            'licencia_tipo', 'identificacion_oficial', 'comprobante_domicilio', 'tipo_vehiculo',
            'marca_vehiculo', 'modelo_vehiculo', 'anio_vehiculo', 'placas', 'color_vehiculo',
            'tarjeta_circulacion', 'seguro_vehiculo', 'cuenta_bancaria', 'clabe', 'banco',
            'titular_cuenta', 'zonas_operacion', 'dias_disponibles', 'horarios_disponibles',
            'antecedentes_penales', 'foto_selfie', 'firma_digital'
        ]
        labels = labels  # Usas el diccionario "labels" que ya tienes en ventasapp.labels



#ESTE ES PARA PODER EDITAR LA CONTRASEÑA
from django.contrib.auth.forms import SetPasswordForm

class CustomPasswordChangeForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})
            
            
            





from django import forms
from .models import Producto
from decimal import Decimal, InvalidOperation

class ProductoForm(forms.ModelForm):
    business_name = forms.CharField(
        label="Negocio asociado",
        required=False,
        disabled=True,
    )

    class Meta:
        model = Producto
        fields = [
            'business', 'tipo_subcategoria', 'name', 'price','ingredientes',
            'image1', 'image2', 'image3', 'image4', 'description','disponible_para_pedido'
        ]

        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'business': forms.HiddenInput(),
            'tipo_subcategoria': forms.HiddenInput(),
        }

        labels = {
            'business': 'Negocio asociado',
            'tipo_subcategoria': 'Tipo de Subcategoría',
            'name': 'Nombre del Producto o Servicio',
            'price': 'Precio en pesos MXN',
            'image1': 'Imagen 1',
            'image2': 'Imagen 2',
            'image3': 'Imagen 3',
            'image4': 'Imagen 4',
            'description': 'Descripción',
        }

    def __init__(self, *args, **kwargs):
        business_instance = kwargs.pop('business_instance', None)
        super().__init__(*args, **kwargs)

        if business_instance:
            self.fields['business_name'].initial = business_instance.commercial_name
            self.fields['business'].initial = business_instance
            self.fields['tipo_subcategoria'].initial = business_instance.tipos_de_negocio

    # Permitir .99 o ,99 para price
    def clean_price(self):
        value = self.cleaned_data.get('price')
        if isinstance(value, str):
            value = value.replace(',', '.')
        try:
            return Decimal(value)
        except (InvalidOperation, TypeError):
            raise forms.ValidationError("Por favor ingresa un precio válido, como 99.99 o 99,99.")

    # Permitir .99 o ,99 para precio_de_envio
    def clean_precio_de_envio(self):
        value = self.cleaned_data.get('precio_de_envio')
        if isinstance(value, str):
            value = value.replace(',', '.')
        try:
            return Decimal(value)
        except (InvalidOperation, TypeError):
            raise forms.ValidationError("Por favor ingresa un costo de envío válido, como 49.99 o 49,99.")



class ExtraForm(forms.ModelForm):
    class Meta:
        model = Extra
        fields = ['nombre', 'precio']
        labels = {
            'nombre': 'Título del Extra',
            'precio': 'Precio del Extra',
            
        }
    def clean_precio(self):
                value = self.cleaned_data.get('precio')
                if isinstance(value, str):
                    value = value.replace(',', '.')
                try:
                    return Decimal(value)
                except (InvalidOperation, TypeError):
                    raise forms.ValidationError("Por favor ingresa un precio válido, como 99.99 o 99,99.")




class ContactForm(forms.Form):
    company_name = forms.CharField(max_length=100)
    name = forms.CharField(max_length=100)
    email = forms.EmailField()    
    phone = forms.CharField(
        max_length=15, 
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$', 
            message="El Formato del Numero debe ser: '+999999999'. Mas de 15 digitos permitidos."
        )]
    )
    message = forms.CharField(widget=forms.Textarea,help_text="Descripcion de la Empresa")
    
    
    
    
    
    # forms.py

        




from django import forms
from .models import DireccionDeEnvio

from .models import Business,Producto,UserProfile,CATEGORY_TYPES, CITIES,DAYS_OF_WEEK,ConductorUser,Extra
from django import forms
from datetime import datetime, timedelta 
from django.core.validators import RegexValidator
from django.contrib.auth.models import User
from ventasapp.labels import labels 


def generate_time_choices(step_minutes=30):
    from datetime import timedelta
    times = []
    current = datetime(2000, 1, 1, 0, 0)
    end = datetime(2000, 1, 2, 0, 0)
    while current <= end:
        value = current.strftime('%H:%M:%S')              
        label = current.strftime('%I:%M %p').lstrip('0')   
        times.append((value, label))
        current += timedelta(minutes=step_minutes)
    return times


def get_grouped_category_choices():
    grouped = []
    for categoria, opciones in CATEGORY_TYPES.items():
        label = categoria.replace('_', ' ').capitalize()
        grouped.append((label, opciones))
    return grouped



class BusinessForm(forms.ModelForm):
    
    tipos_de_negocio = forms.ChoiceField(
    required=False,
    widget=forms.Select,  #AQUI ESTA EL SELECT
    choices=get_grouped_category_choices(),
    label="Tipos de negocio"
    )

    closed_days = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple,
        choices=DAYS_OF_WEEK,
        label="Días cerrados",
        help_text="Selecciona los días en los que el negocio está cerrado."
    )

    opening_time = forms.ChoiceField(
        choices=generate_time_choices(),
        label="Hora de apertura"
    )
    closing_time = forms.ChoiceField(
        choices=generate_time_choices(),
        label="Hora de cierre"
    )

    class Meta:
        model = Business
        exclude = ['owner','city']  # ❗ Prevent manual assignment of the owner in the form
        labels = {
            'commercial_name': 'Nombre comercial',
            'time_category': 'Horario principal',
            'manager_name': 'Nombre del gerente o responsable',
            'owner_or_manager_whatsapp': 'WhatsApp del gerente o dueño',
            'owner_or_manager_email': 'Correo del gerente o dueño',
            'reservations_contact_name': 'Nombre para contacto de reservaciones',
            'reservations_whatsapp': 'WhatsApp para reservaciones',
            'reservations_email': 'Correo para reservaciones',
            'current_promotions': 'Promociones actuales',
            'image1': 'Imagen destacada 1',
            'image2': 'Imagen destacada 2',
            'image3': 'Imagen destacada 3',
            'image4': 'Imagen destacada 4',
            'address': 'Dirección del negocio',
            'website': 'Sitio web (opcional)',
            'stripe_id':'Stripe ID',
            'google_maps':'Locación en Google Maps',
            'description': 'Descripción detallada del negocio',
            
        }
        widgets = {
                'commissions': forms.NumberInput(attrs={
                'placeholder': ' Solo Números'
            })
            }

    def __init__(self, *args, **kwargs):
        super(BusinessForm, self).__init__(*args, **kwargs)
        self.fields['owner_or_manager_whatsapp'].widget.attrs.update({
            'placeholder': ' No espacios, Ej: +525581154023'
        })
        self.fields['reservations_whatsapp'].widget.attrs.update({
            'placeholder': ' No espacios, Ej: +525581154023'
        })
        

        # Pre-fill tipos_de_negocio from stored CSV string
        if self.instance and self.instance.tipos_de_negocio:
            self.initial['tipos_de_negocio'] = self.instance.tipos_de_negocio.split(',')

        # Pre-fill closed_days from stored CSV string
        if self.instance and self.instance.closed_days:
            self.initial['closed_days'] = self.instance.closed_days.split(',')

        # Pre-fill opening and closing times
        if self.instance and self.instance.opening_time:
            self.initial['opening_time'] = self.instance.opening_time.strftime('%H:%M:%S')
        if self.instance and self.instance.closing_time:
            self.initial['closing_time'] = self.instance.closing_time.strftime('%H:%M:%S')
            
    def clean_tipos_de_negocio(self):
        return self.cleaned_data.get('tipos_de_negocio', '')

    def clean_closed_days(self):
        data = self.cleaned_data.get('closed_days', [])
        return ','.join(data)

    def clean_opening_time(self):
        value = self.cleaned_data['opening_time']
        return datetime.strptime(value, '%H:%M:%S').time()

    def clean_closing_time(self):
        value = self.cleaned_data['closing_time']
        return datetime.strptime(value, '%H:%M:%S').time()








class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput,#######ESTE ES PARA LA MERA CONTRASEÑA
        label="Contraseña"
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput,#############ESTE ES PARA LA CONFIRMACION DE LA CONTRASEÑA
        label="Confirmar Contraseña"
    )

    class Meta:
        model = User
        fields = ['username', 'email','first_name','last_name' ,'password']
        labels = {
            'username': 'Nombre de usuario (con este iniciaras sesión)',#######AQUI ESTOY LLAMANDO DEL MODELO USER LA CONTRASEÑA EMAIL Y USERNAME
            'password': 'Contraseña',
             'first_name':'Tu Nombre',
            'last_name':'Apellidos',
            'email':'Correo Electronico',
        }

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get('password') != cleaned_data.get('confirm_password'):
            raise forms.ValidationError("Las contraseñas no coinciden.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])  # Hash the password
        user.email = self.cleaned_data["email"]  # Ensure email is set
        if commit:
            user.save()
        return user


########ESTOS SON PARA REGISTRAR AL USUARIO
class BusinessOwnerProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile##AQUI PARA QUE SE REGISTRE UN DUEÑO DE NEGOCIO ESTAMOS PIDIENDO ESTOS DATOS
        fields = ['city','company_name', 'giro_de_negocio','telephone','profile_picture', 'role','stripe_secret_key']
        labels = {
            
            'city': 'Ciudad',
            'company_name':'Nombre de tu Negocio',
            'telephone':'Numero de Telefono',
            'profile_picture': 'Foto de perfil',
            'giro_de_negocio':'Giro de Negocio'
        }
        widgets = {'role': forms.HiddenInput(),#ESTE LO ESTAMOS OCULTANDO PORQUE YA DESDE QUE ENTRA YA ENTRA AL METODO DE REGISTRO DE PROPIETARIO ENTONCES NO ES NECESARIO QUE ELIJA EL ROL DE NUEVO
        'profile_picture': forms.FileInput(attrs={'class': 'foto-perfil'})
        }
        


class ConductorProfileForm(forms.ModelForm):
        class Meta:
            model=ConductorUser
            fields = [
            'fecha_nacimiento', 'nacionalidad', 'curp', 'telefono', 'direccion', 'city', 'estado',
            'codigo_postal', 'licencia_numero', 'licencia_fecha_emision', 'licencia_fecha_vencimiento',
            'licencia_tipo', 'identificacion_oficial', 'comprobante_domicilio', 'tipo_vehiculo',
            'marca_vehiculo', 'modelo_vehiculo', 'anio_vehiculo', 'placas', 'color_vehiculo',
            'tarjeta_circulacion', 'seguro_vehiculo', 'cuenta_bancaria', 'clabe', 'banco',
            'titular_cuenta', 'zonas_operacion', 'dias_disponibles', 'horarios_disponibles',
            'antecedentes_penales', 'foto_selfie', 'firma_digital'
        ]
            labels= labels
        
        
        

############## ESTO PARA EDITAR LOS DATOS DE USUARIO DEL MODELO User      
class EditUserForm(forms.ModelForm):
    password = forms.CharField(
        label="Nueva contraseña",
        widget=forms.PasswordInput,
        required=False,
    )
    password_confirm = forms.CharField(
        label="Confirmar nueva contraseña",
        widget=forms.PasswordInput,
        required=False,
    )

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name']
        labels = {
            'first_name': 'Nombre',
            'last_name': 'Apellidos',
            'email': 'Correo electrónico',
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")

        if password or password_confirm:
            if password != password_confirm:
                self.add_error("password_confirm", "Las contraseñas no coinciden.")
        return cleaned_data

###ESTE PARA EDITAR LOS CAMPOS DEL MODELO DE UserProfile
class EditBusinessOwnerProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = [ 'company_name','telephone','profile_picture']
        widgets = {'role': forms.HiddenInput()}
        labels = {
            'profile_picture': 'Foto de perfil',
            'company_name':"Nombre de Compañia",
            
        }
        


class EditarConductorProfile(forms.ModelForm):
    class Meta:
        model = ConductorUser
        fields = [
            'fecha_nacimiento', 'nacionalidad', 'curp', 'telefono', 'direccion', 'city', 'estado',
            'codigo_postal', 'licencia_numero', 'licencia_fecha_emision', 'licencia_fecha_vencimiento',
            'licencia_tipo', 'identificacion_oficial', 'comprobante_domicilio', 'tipo_vehiculo',
            'marca_vehiculo', 'modelo_vehiculo', 'anio_vehiculo', 'placas', 'color_vehiculo',
            'tarjeta_circulacion', 'seguro_vehiculo', 'cuenta_bancaria', 'clabe', 'banco',
            'titular_cuenta', 'zonas_operacion', 'dias_disponibles', 'horarios_disponibles',
            'antecedentes_penales', 'foto_selfie', 'firma_digital'
        ]
        labels = labels  # Usas el diccionario "labels" que ya tienes en ventasapp.labels



#ESTE ES PARA PODER EDITAR LA CONTRASEÑA
from django.contrib.auth.forms import SetPasswordForm

class CustomPasswordChangeForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})
            
            
            





from django import forms
from .models import Producto
from decimal import Decimal, InvalidOperation

class ProductoForm(forms.ModelForm):
    business_name = forms.CharField(
        label="Negocio asociado",
        required=False,
        disabled=True,
    )

    class Meta:
        model = Producto
        fields = [
            'business', 'tipo_subcategoria', 'name', 'price','ingredientes',
            'image1', 'image2', 'image3', 'image4', 'description','disponible_para_pedido'
        ]

        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'business': forms.HiddenInput(),
            'tipo_subcategoria': forms.HiddenInput(),
        }

        labels = {
            'business': 'Negocio asociado',
            'tipo_subcategoria': 'Tipo de Subcategoría',
            'name': 'Nombre del Producto o Servicio',
            'price': 'Precio en pesos MXN',
            'image1': 'Imagen 1',
            'image2': 'Imagen 2',
            'image3': 'Imagen 3',
            'image4': 'Imagen 4',
            'description': 'Descripción',
        }

    def __init__(self, *args, **kwargs):
        business_instance = kwargs.pop('business_instance', None)
        super().__init__(*args, **kwargs)

        if business_instance:
            self.fields['business_name'].initial = business_instance.commercial_name
            self.fields['business'].initial = business_instance
            self.fields['tipo_subcategoria'].initial = business_instance.tipos_de_negocio

    # Permitir .99 o ,99 para price
    def clean_price(self):
        value = self.cleaned_data.get('price')
        if isinstance(value, str):
            value = value.replace(',', '.')
        try:
            return Decimal(value)
        except (InvalidOperation, TypeError):
            raise forms.ValidationError("Por favor ingresa un precio válido, como 99.99 o 99,99.")

    # Permitir .99 o ,99 para precio_de_envio
    def clean_precio_de_envio(self):
        value = self.cleaned_data.get('precio_de_envio')
        if isinstance(value, str):
            value = value.replace(',', '.')
        try:
            return Decimal(value)
        except (InvalidOperation, TypeError):
            raise forms.ValidationError("Por favor ingresa un costo de envío válido, como 49.99 o 49,99.")



class ExtraForm(forms.ModelForm):
    class Meta:
        model = Extra
        fields = ['nombre', 'precio']
        labels = {
            'nombre': 'Título del Extra',
            'precio': 'Precio del Extra',
            
        }
    def clean_precio(self):
                value = self.cleaned_data.get('precio')
                if isinstance(value, str):
                    value = value.replace(',', '.')
                try:
                    return Decimal(value)
                except (InvalidOperation, TypeError):
                    raise forms.ValidationError("Por favor ingresa un precio válido, como 99.99 o 99,99.")




class ContactForm(forms.Form):
    company_name = forms.CharField(max_length=100)
    name = forms.CharField(max_length=100)
    email = forms.EmailField()    
    phone = forms.CharField(
        max_length=15, 
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$', 
            message="El Formato del Numero debe ser: '+999999999'. Mas de 15 digitos permitidos."
        )]
    )
    message = forms.CharField(widget=forms.Textarea,help_text="Descripcion de la Empresa")
    
    
    
    
    
    # forms.py

        




from django import forms
from .models import DireccionDeEnvio

class DireccionDeEnvioForm(forms.ModelForm):
    class Meta:
        model = DireccionDeEnvio
        fields = '__all__'  # puedes cambiarlo por una lista explícita si prefieres
   
    telefono = forms.CharField(
        label='Teléfono',
        widget=forms.TextInput(attrs={'placeholder': 'Ej. +52 55 1234 5678'})
    )
    
    def __init__(self, *args, **kwargs):
        # NUEVO: Recibir opciones de entrega dinámicas
        opciones_entrega = kwargs.pop('opciones_entrega', None)
        super().__init__(*args, **kwargs)
        
        # Si se pasan opciones de entrega, usar esas; si no, usar las por defecto
        if opciones_entrega:
            self.fields['opcion_entrega'].choices = opciones_entrega
            
            # Si solo hay una opción (retiro en sucursal), pre-seleccionarla
            if len(opciones_entrega) == 1:
                self.fields['opcion_entrega'].initial = opciones_entrega[0][0]
                
                # Opcional: hacer que el campo sea readonly si solo hay una opción
                self.fields['opcion_entrega'].widget.attrs.update({
                    'readonly': True,
                    'style': 'background-color: #f8f9fa; cursor: not-allowed;'
                })
        else:
            # Usar las opciones por defecto del modelo
            self.fields['opcion_entrega'].choices = OPCIONES_ENTREGA
    
    def clean(self):
        cleaned_data = super().clean()
        opcion = cleaned_data.get('opcion_entrega')
        decidir_despues = cleaned_data.get('decidir_propina_despues')
        propina = cleaned_data.get('propina_voluntaria')
        
        # Validar dirección si es entrega a domicilio
        if opcion == 'domicilio':
            required_fields = ['direccion', 'ciudad', 'estado', 'codigo_postal']
            for field in required_fields:
                if not cleaned_data.get(field):
                    self.add_error(field, 'Este campo es obligatorio para entrega a domicilio.')
        
        # Validar propina si no decide después
        if not decidir_despues:
            if propina is None:
                self.add_error('propina_voluntaria', 'Debes ingresar una propina o marcar "Decidir propina después".')
            elif propina < 0:
                self.add_error('propina_voluntaria', 'La propina no puede ser negativa.')
        
        return cleaned_data







# PARA CONECTAR EL USUARIO AL STRIPE DE MI CUENTA , ESO ES PARA QUE MI CUENTA COMO PLATAFORMA TRANSFIERA EL DINERO AL CLIENTE
from django import forms

class StripeConnectForm(forms.Form):
    stripe_account_id = forms.CharField(
        label="Stripe Account ID",
        max_length=255,
        help_text="Pega aquí tu ID de cuenta Stripe (ej. acct_1234...)"
    )








# PARA CONECTAR EL USUARIO AL STRIPE DE MI CUENTA , ESO ES PARA QUE MI CUENTA COMO PLATAFORMA TRANSFIERA EL DINERO AL CLIENTE
from django import forms

class StripeConnectForm(forms.Form):
    stripe_account_id = forms.CharField(
        label="Stripe Account ID",
        max_length=255,
        help_text="Pega aquí tu ID de cuenta Stripe (ej. acct_1234...)"
    )
