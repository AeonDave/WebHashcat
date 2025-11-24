#!/bin/bash

sleep 2

# Try standard migrate, then fallback to fake-initial if the schema already exists
if ! python3 manage.py migrate --noinput; then
  echo "Standard migrate failed, retrying with --fake-initial"
  python3 manage.py migrate --noinput --fake-initial
fi

if [[ ! -z "${DJANGO_SUPERUSER_USERNAME}" ]]; then
python3 -c "import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'WebHashcat.settings'
import django
django.setup()
from django.contrib.auth.management.commands.createsuperuser import get_user_model
if get_user_model().objects.filter(username='$DJANGO_SUPERUSER_USERNAME'):
    print('Super user already exists. SKIPPING...')
else:
    print('Creating super user...')
    get_user_model()._default_manager.db_manager('default').create_superuser(username='$DJANGO_SUPERUSER_USERNAME', email='$DJANGO_SUPERUSER_EMAIL', password='$DJANGO_SUPERUSER_PASSWORD')
    print('Super user created...')"
fi


exec "$@"
