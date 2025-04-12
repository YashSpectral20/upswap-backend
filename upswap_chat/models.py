import uuid

from django.db import models
from django.utils import timezone
from main.models import (
    CustomUser,
    Activity
)

class ChatRequest(models.Model):
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE)
    from_user = models.ForeignKey(CustomUser, related_name='sent_requests', on_delete=models.CASCADE)
    is_accepted = models.BooleanField(default=False, help_text="True if the request is accepted")
    is_clicked = models.BooleanField(default=False, help_text="True if request was interacted with")  # ✅ NEW FIELD
    initial_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    def accept(self):
        self.is_accepted = True
        self.is_clicked = True
        chat_room, created = ChatRoom.objects.get_or_create(activity=self.activity)
        chat_room.participants.add(self.from_user, self.activity.created_by)
        chat_room.save()
        self.save()
        if self.initial_message:
            ChatMessage.objects.create(
                chat_room=chat_room,
                sender=self.from_user,
                content=self.initial_message
            )
        return chat_room

    def __str__(self):
        return f"Request from {self.from_user} to {self.activity.created_by} for {self.activity}"

class ChatRoom(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE)
    participants = models.ManyToManyField(CustomUser)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"ChatRoom {self.id} for Activity {self.activity.activity_title}"

class ChatMessage(models.Model):
    chat_room = models.ForeignKey(ChatRoom, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(CustomUser, related_name='sent_messages', on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-created_at',)
        
    def __str__(self):
        return f"Message {self.id} from {self.sender.email}"