from django.apps import AppConfig


class VentasappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ventasapp'
    
    def ready(self):
        import ventasapp.signals  #Esto es necesario para activar las señales, ESTO ES PARA QUE SE ELIMINEN LAS IMAGENES CUANDO SE ELIMINA UN PRODCTO



