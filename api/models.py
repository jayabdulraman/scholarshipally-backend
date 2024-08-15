from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
import uuid

class CustomUserManager(BaseUserManager):

    def create_superuser(self, fullname, email, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Super user must be assigned to staff status")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Super user must be assign to super user status")

        return self.create_user(fullname, email, password, **extra_fields)

    def create_user(self, fullname, email, password, **extra_fields):

        if not email:
            raise ValueError("Email is required")

        user = self.model(fullname=fullname, email=email, **extra_fields)

        user.set_password(password)

        user.save()

        return user
    
class User(AbstractBaseUser, PermissionsMixin):
    fullname = models.CharField("Full name", max_length=100, blank=False)
    email = models.EmailField("Email Address", max_length=100, blank=False, null=False, unique=True)
    custom_instruction = models.TextField("Custom Instruction", max_length=250, blank=True, null=True)
    phone_number = models.CharField("Phone Number", blank=True, null=True, max_length=50)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    updatedAt = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['fullname']

    objects = CustomUserManager()

    def __str__(self):
        return self.fullname
    
class Threads(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False)
    title = models.CharField('Title', null=False, blank=False, max_length=150)
    user = models.ForeignKey(User, on_delete=models.RESTRICT)
    path =  models.CharField("Path", max_length=200, null=True, blank=True)
    createdAt = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.title
    
class Chats(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False)
    role_choices = (('user', 'user'), ('assistant', 'assistant'), ('system', 'system'), ('tool', 'tool'))
    role = models.CharField('Role', choices=role_choices, null=False, blank=False, max_length=50)
    content = models.TextField('Content', null=False, blank=False, max_length=500)
    metadata =  models.JSONField("Metadata", max_length=200, null=True, blank=True)
    search_choices = (('DatabaseSearch', 'DatabaseSearch'), ('GoogleSearch', 'GoogleSearch'))
    searchType = models.CharField('SearchType', default="DatabaseSearch", choices=search_choices, null=False, blank=False, max_length=50)
    threadId = models.ForeignKey(Threads, on_delete=models.CASCADE)
    createdAt = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.role
    
class Feedback(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False)
    value = models.BooleanField('Like or Dislike', null=False, blank=False)
    comment = models.TextField(null=True, blank=True, max_length=100)
    chatId = models.ForeignKey(Chats, on_delete=models.RESTRICT)
    userId = models.ForeignKey(User, on_delete=models.RESTRICT)
    createdAt = models.DateTimeField(default=timezone.now)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.comment

class Favorites(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False)
    name = models.CharField('Name', null=False, blank=False, max_length=50)
    description = models.TextField('Description', null=False, blank=False, max_length=150)
    eligibility = models.TextField('Eligbility', null=True, blank=True, max_length=150)
    value = models.CharField('Value', null=True, blank=True, max_length=100)
    fields = models.CharField('Fields', null=True, blank=True, max_length=100)
    deadline = models.CharField('Deadline', null=False, blank=False, max_length=100)
    website = models.CharField('Website', null=False, blank=False, max_length=100)
    track = models.BooleanField(default=False, null=True, blank=True)
    choices = (('Two times before deadline', 'Two times before deadline'), ('Three times before deadline', 'Three times before deadline'))
    remind_me = models.CharField('Reminder options', choices=choices, null=True, blank=True, max_length=50)
    userId = models.ForeignKey(User, on_delete=models.RESTRICT)
    createdAt = models.DateTimeField(default=timezone.now)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class Scholarships(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False)
    name = models.CharField('Name', null=False, blank=False, max_length=50)
    description = models.TextField('Description', null=False, blank=False, max_length=150)
    eligibility = models.TextField('Eligbility', null=True, blank=True, max_length=150)
    value = models.CharField('Value', null=True, blank=True, max_length=100)
    fields = models.CharField('Fields', null=True, blank=True, max_length=100)
    deadline = models.DateTimeField('Deadline', null=False, blank=False)
    hostCountry = models.CharField('Host Country', null=False, blank=False, max_length=100)
    website = models.CharField('Website', null=False, blank=False, max_length=100)
    createdAt = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.name

class RateLimit(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    last_request = models.DateTimeField()
    request_count = models.IntegerField(default=0)
    createdAt = models.DateTimeField(default=timezone.now)