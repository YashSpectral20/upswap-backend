import uuid

from django.db import models
from django.utils import timezone
from main.models import (
    CustomUser,
    Activity
)
from main.utils import create_notification

class ChatRequest(models.Model):
    PARTICIPATION_STATUSES = [
        ('PENDING', 'pending'),
        ('ACCEPTED', 'accepted'),
        ('REJECTED', 'rejected')
    ]
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE, related_name='chat_requests')
    from_user = models.ForeignKey(CustomUser, related_name='sent_requests', on_delete=models.CASCADE)
    is_accepted = models.BooleanField(default=False, help_text="True if the request is accepted")
    is_clicked = models.BooleanField(default=False, help_text="True if request was interacted with")
    is_undo = models.BooleanField(default=False, help_text="True if user wants to undo the action")
    is_rejected = models.BooleanField(default=False, help_text="True if the request is rejected")
    initial_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    participation_status = models.CharField(default='PENDING', choices=PARTICIPATION_STATUSES)

    def accept(self):
        self.is_accepted = True
        self.is_clicked = True
        self.is_rejected = False

        # Create new chat room if it doesn't exist
        chat_room = ChatRoom.objects.create(activity=self.activity, chat_request = self)
        chat_room.participants.add(self.from_user, self.activity.created_by)
        chat_room.save()
        self.save()

        if self.initial_message:
            ChatMessage.objects.create(
                chat_room=chat_room,
                sender=self.from_user,
                content=self.initial_message
            )
            
        # Create notification for the user who sent the request
        create_notification(
            user=self.from_user,
            notification_type="activity",  # or "general"
            title="Your Chat Request was Accepted",
            body=f"{self.activity.created_by.name} accepted your request for activity: {self.activity.activity_title}",
            reference_instance=self.activity,
            data={"activity_id": str(self.activity.activity_id)}
        )

        return chat_room


    def __str__(self):
        return f"Request from {self.from_user} to {self.activity.created_by} for {self.activity}"

class ChatRoom(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE)   # SET_NULL
    participants = models.ManyToManyField(CustomUser)
    created_at = models.DateTimeField(auto_now_add=True)
    chat_request = models.ForeignKey(ChatRequest, on_delete=models.SET_NULL, null=True, blank=True, related_name='chat_room')
    
    def __str__(self):
        return f"ChatRoom {self.id} for Activity {self.activity.activity_title}"

class ChatMessage(models.Model):
    chat_room = models.ForeignKey(ChatRoom, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(CustomUser, related_name='sent_messages', on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    seen_by = models.ManyToManyField(CustomUser, related_name='seen_messages', blank=True)

    class Meta:
        ordering = ('-created_at',)
        
    def __str__(self):
        return f"Message {self.id} from {self.sender.email}"