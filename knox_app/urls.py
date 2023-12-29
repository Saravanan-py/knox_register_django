from django.urls import path, include
from knox_app import views
from django.urls import path, include
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions
from knox import views as knox_views

# noinspection PyTypeChecker
schema_view = get_schema_view(
    openapi.Info(
        title="Snippets API",
        default_version='v1',
        description="Test description",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@snippets.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('verification/email/', views.Email_API.as_view()),
    path('verification/otpcheck/', views.OTPCheck_API.as_view()),
    path('verification/licensecheck/', views.LicenseCheck_API.as_view()),
    path('create/', views.RegisterUser.as_view()),
    path('login/', views.LoginAPI.as_view()),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('logout/', knox_views.LogoutView.as_view(), name='knox_logout'),
    path('logoutall/', knox_views.LogoutAllView.as_view(), name='knox_logoutall'),
]