from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import RegexValidator
from django.contrib.auth.password_validation import validate_password

class MyAccountManager(BaseUserManager):
    def create_user(self, full_name, username, password=None, email=None, phone=None):
        if not username:
            raise ValueError("User must have a username")
        if not full_name:
            raise ValueError("User must have a full name")

        user = self.model(
            username=username,
            full_name=full_name,
            email=self.normalize_email(email) if email else None,
            phone=phone,
        )

        validate_password(password, user)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, full_name, username, password, email=None):
        user = self.create_user(
            username=username,
            full_name=full_name,
            password=password,
            email=email
        )
        user.is_superuser = True
        user.is_active = True
        user.is_staff = True
        user.save(using=self._db)
        return user
class User(AbstractBaseUser):
    full_name = models.CharField(max_length=50)
    email = models.EmailField(verbose_name='email address', max_length=255, unique=True, null=True, blank=True)
    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")]
    )
    username = models.CharField(max_length=50, unique=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    objects = MyAccountManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['full_name']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return True


class Post(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    title = models.CharField(max_length=255)
    description = models.TextField()
    tags = models.CharField(max_length=255, help_text="Comma-separated tags")
    created_at = models.DateTimeField(auto_now_add=True)
    published = models.BooleanField(default=True)
    likes = models.PositiveIntegerField(default=0)
    liked_by = models.ManyToManyField(User, related_name='liked_posts', blank=True)  # New field

    def __str__(self):
        return self.title
