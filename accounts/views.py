from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from .forms import RegistrationForm
from .models import Account
import requests

from carts.views import _cart_id
from carts.models import Cart, CartItem
from store.models import Product

# Create your views here.
def register(request):
    form = RegistrationForm()
    if request.method == 'POST':
        form = RegistrationForm(request.POST or None)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']

            username = email.split('@')[0]
        

            user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
            user.phone_number = phone_number
            user.save()

            current_site = get_current_site(request)
            mail_subject = 'Por favor activa tu cuenta'
            body = render_to_string('accounts/account_verification_email.html',{
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, body, to=[to_email])
            send_email.send()   

            #messages.success(request, 'Usuario Registrado Correctamente.')

            return redirect('/accounts/login/?command=verification&email='+email)



    context = {
        'form': form
    }

    return render(request, 'accounts/register.html', context)

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = auth.authenticate(email=email, password=password)
        if user is not None:
            # MIGRAR Y FUSIONAR CARRITO DE SESIÓN AL USUARIO
            try:
                cart = Cart.objects.get(cart_id=_cart_id(request))
                session_cart_items = CartItem.objects.filter(cart=cart)
                for session_item in session_cart_items:
                    # Busca si el usuario ya tiene ese producto y variaciones
                    user_cart_items = CartItem.objects.filter(
                        user=user,
                        product=session_item.product,
                    )
                    found = False
                    for user_item in user_cart_items:
                        if set(user_item.variations.all()) == set(session_item.variations.all()):
                            # Si existe, suma cantidades y elimina el de sesión
                            user_item.quantity += session_item.quantity
                            user_item.save()
                            session_item.delete()
                            found = True
                            break
                    if not found:
                        # Si no existe, asocia el item al usuario
                        session_item.user = user
                        session_item.cart = None
                        session_item.save()
            except Cart.DoesNotExist:
                pass

            auth.login(request, user)
            messages.success(request, 'Has iniciado sesión correctamente.')

            url = request.META.get('HTTP_REFERER')
            try:
                query = requests.utils.urlparse(url).query
                params = dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextpage = params['next']
                    return redirect(nextpage)
            except:
                return redirect('dashboard')

        else:
            messages.error(request, 'Credenciales inválidas')
            return redirect('login')
        
    return render(request, 'accounts/login.html')

@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request, 'Has cerrado sesión correctamente.')
    return redirect('login')

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Felicidades! Tu cuenta ha sido activada.')
        return redirect('login')
    else:
        messages.error(request, 'El enlace de activación no es válido.')
        return redirect('register')
    

@login_required(login_url='login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')

def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)

            current_site = get_current_site(request)
            mail_subject = 'Restablecer tu contraseña'
            body = render_to_string('accounts/reset_password_email.html',{
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, body, to=[to_email])
            send_email.send()   

            messages.success(request, 'Hemos enviado un email a tu cuenta de correo para restablecer tu contraseña.')
            return redirect('login')
        else:
            messages.error(request, 'La cuenta no existe.')
            return redirect('forgotPassword')

    return render(request, 'accounts/forgotPassword.html')

def resetpassword_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Por favor restablece tu contraseña.')
        return redirect('resetPassword')
    else:
        messages.error(request, 'El enlace ha expirado.')
        return redirect('login')

def resetPassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Contraseña restablecida correctamente.')
            return redirect('login')
        else:
            messages.error(request, 'Las contraseñas no coinciden.')
            return redirect('resetPassword')
    else:
        return render(request, 'accounts/resetPassword.html')