# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'user_demo',
        'HOST': '127.0.0.1',
        'PORT': '3306',
        'USER': 'user',
        'PASSWORD': 'Vishakha@2021',
    },
}