from .models import Cart
from django.db.models import Sum
############3 ESTA VISTA LA CREE PARA PODERLE PONER LA CONDICIONAL AL BOTON DEL CARRITO EN TODAS LAS VISTAS QUE QUIERA, ESTO ACOMPAÑADO DE UN POCO DE CODIGO LLAMADO OPCIONES EN EL settings.py 
def carrito_items_count(request):
    try:
        if not request.session.session_key:
            request.session.create()

        session_key = request.session.session_key
        cart = Cart.objects.filter(session_key=session_key).first()

        total_items = 0
        if cart:
            total_items = cart.items.aggregate(total=Sum('cantidad'))['total'] or 0

        return {'items_carrito': total_items}
    except:
        return {'items_carrito': 0}