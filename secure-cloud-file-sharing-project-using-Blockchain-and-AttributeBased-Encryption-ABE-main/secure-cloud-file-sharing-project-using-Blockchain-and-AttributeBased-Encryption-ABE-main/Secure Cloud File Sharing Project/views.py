from django.shortcuts import render,redirect
from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect
from .models import *
from .new1 import *
import hashlib

from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
import os
from django.contrib import messages


def home(request):
    return render(request, 'home.html')
def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        private_key = request.POST['etherun_private_key']
        try:
            user = RegUser.objects.get(username=username)
            if user.password == password:
                if user.private_key == private_key:
                    messages.warning(request, 'Login Successful')
                    user_data, private_key = login_user(username, password, private_key)
                    print(user_data, private_key)
                    print(type(private_key))
                    return redirect(reverse('index',kwargs={'private_key': private_key}))
                else:
                    messages.warning(request, 'Incorrect Etherum Private key.')
            else:
                messages.warning(request, 'Invalid password.')

        except RegUser.DoesNotExist:
            messages.warning(request, 'Invalid username')
        
    return render(request, 'login.html')

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        private_key = request.POST.get('etherun_private_key')
        name = request.POST.get('name')
        email = request.POST.get('email')
        department = request.POST.get('department')
        subscription_period = request.POST.get('subscription')
        try:
            user = RegUser.objects.get(username=username)
            if user:
                messages.warning(request, 'Username already exists')
                pass
        except RegUser.DoesNotExist:
            user = RegUser(username=username, password=password, private_key=private_key, name=name, email=email,department=department,subscription_period=subscription_period)
            messages.success(request, 'Registration successful!')
            try:
                userID = register_user(username,password, name, email, department, subscription_period, private_key)
                print(userID)
            except Exception as e:
                messages.warning(request, 'User already exists .Please login')
                pass
            user.save()
            return redirect('index', private_key)
        
    return render(request, 'register.html')


# //////////////////////////////////////////////////////////////////////

def Operations(request, private_key):
    if request.method == 'POST':
        name = request.POST.get('role')
        if name == 'Data Owner':
            return redirect(reverse('owner',kwargs={'private_key': private_key}))
        elif name == 'User':
            return redirect(reverse('user',kwargs={'private_key': private_key}))
    return render(request, 'index.html', {'private_key': private_key})

def owner(request, private_key):
    if request.method == 'POST':
        func = request.POST.get('owner-function')
        if func == 'Upload File':
            return redirect(reverse('upload',kwargs={'private_key': private_key}))
        elif func == 'Grant Access':
            return redirect(reverse('grant',kwargs={'private_key': private_key}))
        elif func == 'Revoke Access':
            return redirect(reverse('revoke',kwargs={'private_key': private_key}))
    return render(request, 'owner.html', {'private_key': private_key})

def user(request, private_key):
    if request.method == 'POST':
        func = request.POST.get('user-function')
        if func == 'Request Access':
            return redirect(reverse('request',kwargs={'private_key': private_key}))
        elif func == 'Download':
            return redirect(reverse('download',kwargs={'private_key': private_key}))
    return render(request, 'user.html', {'private_key': private_key})

def uploader(request, private_key):
    data_owner = DataOwner(private_key)
    if request.method == 'POST':
        # Check if a file is uploaded
        if 'file' in request.FILES:
            uploaded_file = request.FILES['file']
            file_name = uploaded_file.name

            # Define the folder where the file will be saved
            upload_folder = os.path.join(settings.MEDIA_ROOT, 'uploads')

            # Create the folder if it doesn't exist
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)

            # Save the file to the folder
            file_path = os.path.join(upload_folder, file_name)
            with open(file_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

            # Access Policy
            a1 = request.POST.get('department')
            a2 = request.POST.get('subscription')
            access_policy = f"department:{a1}, subscription_period:{a2}"
            #new1.py
            r = data_owner.upload_file(file_path, access_policy)
            # Success message
            if r[0] == 1:
                messages.success(request, f'File "{file_name}" already exists')
                messages.success(request, f'File Metadata updated in blockchain')
            elif r[0] == 2:
                messages.success(request, f'File already exists as "{r[1]}"')
                messages.success(request, f'File Metadata updated in blockchain')
            elif r[0] == 3:
                file_tag = sha256_hash(file_name.encode())
                file = File(file_id=file_tag)
                file.save()
                messages.success(request, f'File "{file_name}"uploaded successfully!')
                messages.success(request, f'File Metadata uploaded into blockchain')
            return redirect(reverse('index',kwargs={'private_key': private_key}))            
            
        else:
            # Error message if no file is selected
            messages.error(request, 'No file selected!')
            return redirect(reverse('upload',kwargs={'private_key': private_key}))
    return render(request, 'upload.html', {'private_key': private_key})

def granter(request, private_key):
    data_owner = DataOwner(private_key)
    owner = RegUser.objects.get(private_key=private_key)
    username = owner.username
    details = []
    
    if request.method == 'POST':
        file = request.POST.get('filename')
        action = request.POST.get('action')
    
        if action == 'check':
            details = data_owner.display_req(file)
            print(details)
            if "File Not Found" in details:
                messages.warning(request, 'File Not Found')
            elif details == []:
                messages.warning(request, 'No Requests Yet')
            else:
                return render(request, 'grant.html', {'details': details, 'private_key': private_key, 'filename':file})
        
        elif action == 'grant':
            details = data_owner.display_req(file)
            data_owner.grant_access(file, details, username)
            messages.success(request, 'Granted Access!')
            return render(request, 'grant.html', {'private_key': private_key})
        #except Exception as e:
         #   messages.warning(request, e)
    return render(request, 'grant.html', {'private_key': private_key})

def revoker(request, private_key):
    data_owner = DataOwner(private_key)
    owner = RegUser.objects.get(private_key=private_key)
    username = owner.username
    if request.method == 'POST':
        filename = request.POST.get('filename')
        action = request.POST.get('action')
        if action == 'Get Users':
            print("Get Users")
            users = data_owner.display_users(filename, username)
            if "File Not Found" in users:
                messages.warning(request, 'File Not Found')
            elif users == []:
                messages.warning(request, 'No Users Found')
            else:
                return render(request, 'revoke.html', {'users': users, 'filename':filename})
        elif action == 'Revoke':
            users = data_owner.display_users(filename, username)
            selected_users = request.POST.getlist('users')
            print(selected_users)
            data_owner.revoke_access(filename, username, selected_users)
            # Process the selected users as needed
            selected_user_details = [user for user in users if user not in selected_users]
            messages.success(request, 'Access Revoked')
            return render(request, 'revoke.html', {'users': selected_user_details, 'filename':filename})

    return render(request, 'revoke.html')

def requester(request, private_key):
    data_user = User(private_key)
    user = RegUser.objects.get(private_key=private_key)
    if request.method == 'POST':
        filename = request.POST.get('filename')
        r = data_user.request_access(filename, user.username)
        # Success message
        if r == 1:
            messages.success(request, f'Request for File:"{filename}" registered successfully!')
            return redirect(reverse('index',kwargs={'private_key': private_key}))
        elif r == -1:
            messages.warning(request, f'File not found')
            return render(request, 'request.html', {'private_key': private_key})
        else:
            messages.warning(request, r)
            return redirect(reverse('index',kwargs={'private_key': private_key}))
    return render(request, 'request.html', {'private_key': private_key})

def downloader(request, private_key):
    data_user = User(private_key)
    user = RegUser.objects.get(private_key=private_key)
    if request.method == 'POST':
        filename = request.POST.get('filename')
        r = data_user.download_and_decrypt_file(filename, user.username)
        # Success message
        if r == 0:
            messages.success(request, f'Request for File:"{filename}" under process')
        elif r == 1:
            messages.success(request, f'Downloaded File:"{filename}" successfully!')
        elif r == 2:
            messages.warning(request, f'Permission Denied')
        elif r == -2:
            messages.warning(request, f'You have not requested access. Permission Denied')
                  
    return render(request, 'download.html', {'private_key': private_key})

def sha256_hash(data):
    """Compute the SHA256 hash of the given data."""
    return hashlib.sha256(data).digest()
