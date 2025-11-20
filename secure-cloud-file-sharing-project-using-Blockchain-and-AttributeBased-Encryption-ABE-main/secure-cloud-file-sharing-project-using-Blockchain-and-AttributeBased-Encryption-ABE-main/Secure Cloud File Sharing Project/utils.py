from .models import File, Subscription

def add_keys(file_id, user_id, keys, names):
    file_obj, _ = File.objects.get_or_create(file_id=file_id)
    enc_keys = [key.hex() if isinstance(key, bytes) else key for key in keys]
    try:
        sub = Subscription.objects.get(file=file_obj, user_id=user_id)
        sub.user_keys = enc_keys
        sub.user_names = names
        sub.save()
    except Subscription.DoesNotExist:
        Subscription.objects.create(
            file=file_obj,
            user_id=user_id,
            user_keys=enc_keys,
            user_names=names
        )

def get_keys(file_id, user_id):
    try:
        file_obj = File.objects.get(file_id=file_id)
        sub = Subscription.objects.get(file=file_obj, user_id=user_id)
        dec_keys = [bytes.fromhex(k) for k in sub.user_keys]
        return dec_keys
    except (File.DoesNotExist, Subscription.DoesNotExist):
        return []

def get_users(file_id, user_id):
    try:
        file_obj = File.objects.get(file_id=file_id)
        sub = Subscription.objects.get(file=file_obj, user_id=user_id)
        return sub.user_names
    except (File.DoesNotExist, Subscription.DoesNotExist):
        return []