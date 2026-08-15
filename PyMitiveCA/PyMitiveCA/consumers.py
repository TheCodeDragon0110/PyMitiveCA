import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from datetime import datetime

class ServerStatusConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.task = asyncio.create_task(self.send_status_periodically())

    async def disconnect(self, close_code):
        self.task.cancel()

    async def send_status_periodically(self):
        try:
            while True:
                data = {
                    "status": "online",
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                await self.send(text_data=json.dumps(data))
                await asyncio.sleep(20)
        except asyncio.CancelledError:
            pass