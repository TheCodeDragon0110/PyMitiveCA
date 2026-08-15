from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path("ws/ca-server-status/", consumers.ServerStatusConsumer.as_asgi()),
]