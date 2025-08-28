#ESTE LO CREE PARA QUE SE ELIMINEN LAS IMAGENES DE LA CARPETA CUANDO SE ELIMINE EL PRODUCTO O SE CAMBIE LA IMAGEN
#TAMBIEN DEBI AGREGAR CAMBIOS EN apps.py PARA QUE SE ACTIVEN ESTOS MEETODOS
from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver
import os

from .models import Business, Producto, UserProfile, ConductorUser

# === ELIMINAR IMÁGENES AL BORRAR ===

@receiver(post_delete, sender=Business)
def eliminar_imagenes_business(sender, instance, **kwargs):
    for img in [instance.image1, instance.image2, instance.image3, instance.image4]:
        if img and img.path and os.path.isfile(img.path):
            os.remove(img.path)

@receiver(post_delete, sender=Producto)
def eliminar_imagenes_producto(sender, instance, **kwargs):
    for img in [instance.image1, instance.image2, instance.image3, instance.image4]:
        if img and img.path and os.path.isfile(img.path):
            os.remove(img.path)

@receiver(post_delete, sender=UserProfile)
def eliminar_imagenes_userprofile(sender, instance, **kwargs):
    for img in [instance.profile_picture, instance.id_document]:
        if img and img.path and os.path.isfile(img.path):
            os.remove(img.path)

@receiver(post_delete, sender=ConductorUser)
def eliminar_imagenes_conductoruser(sender, instance, **kwargs):
    if instance.foto_selfie and instance.foto_selfie.path and os.path.isfile(instance.foto_selfie.path):
        os.remove(instance.foto_selfie.path)

# === REEMPLAZAR IMÁGENES ANTIGUAS AL ACTUALIZAR ===

@receiver(pre_save, sender=Business)
def reemplazar_imagenes_business(sender, instance, **kwargs):
    if not instance.pk:
        return
    try:
        old = Business.objects.get(pk=instance.pk)
    except Business.DoesNotExist:
        return
    for attr in ['image1', 'image2', 'image3', 'image4']:
        old_img = getattr(old, attr)
        new_img = getattr(instance, attr)
        if old_img and old_img != new_img and os.path.isfile(old_img.path):
            os.remove(old_img.path)

@receiver(pre_save, sender=Producto)
def reemplazar_imagenes_producto(sender, instance, **kwargs):
    if not instance.pk:
        return
    try:
        old = Producto.objects.get(pk=instance.pk)
    except Producto.DoesNotExist:
        return
    for attr in ['image1', 'image2', 'image3', 'image4']:
        old_img = getattr(old, attr)
        new_img = getattr(instance, attr)
        if old_img and old_img != new_img and os.path.isfile(old_img.path):
            os.remove(old_img.path)

@receiver(pre_save, sender=UserProfile)
def reemplazar_imagenes_userprofile(sender, instance, **kwargs):
    if not instance.pk:
        return
    try:
        old = UserProfile.objects.get(pk=instance.pk)
    except UserProfile.DoesNotExist:
        return
    for attr in ['profile_picture', 'id_document']:
        old_img = getattr(old, attr)
        new_img = getattr(instance, attr)
        if old_img and old_img != new_img and os.path.isfile(old_img.path):
            os.remove(old_img.path)

@receiver(pre_save, sender=ConductorUser)
def reemplazar_imagenes_conductoruser(sender, instance, **kwargs):
    if not instance.pk:
        return
    try:
        old = ConductorUser.objects.get(pk=instance.pk)
    except ConductorUser.DoesNotExist:
        return
    old_img = old.foto_selfie
    new_img = instance.foto_selfie
    if old_img and old_img != new_img and os.path.isfile(old_img.path):
        os.remove(old_img.path)
