
from django import template

register = template.Library()

@register.filter#ESTE ES EL QUE SACA LOS BOTONES
def get_item(dictionary, key):
    return dictionary.get(key)

#CON ESTOS SON LOS QUE ESTOY SACANDO LAS PROPIEDADES POR CATEGORIAS
@register.filter
def pluck(value, index):
    return [item[index] for item in value]

@register.filter
def dictfilterbytypes(businesses, type_codes):
    return [b for b in businesses if any(code in (b.tipos_de_negocio or '') for code in type_codes)]

@register.filter
def get_attr(obj, attr_name):
    return getattr(obj, attr_name, None)




