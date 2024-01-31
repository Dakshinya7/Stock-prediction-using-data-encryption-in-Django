from django.urls import path
from .views import home
from .views import login
from .views import logout

urlpatterns = [
    path('', login, name='login'),  # Set the login view as the root URL
    path('home/', home, name='home'),
    path('login/', login, name='login'),
    path('logout/', logout, name='logout')
]
