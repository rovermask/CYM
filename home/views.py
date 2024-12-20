from django.shortcuts import render
import encryption_algorithms.rsa_algo as ra
import encryption_algorithms.substitution_cipher as sc
import encryption_algorithms.swapping_algo as sa


# Create your views here.
def home(request):
    return render(request,"home.html")

def documentation(request):
    return render(request,"documentation.html")

def examples(request):
    return render(request,"examples.html")

def about(request):
    return render(request,"about.html")

def symmetric(request):
    return render(request,"symmetric.html")

def asymmetric(request):
    return render(request,"asymmetric.html")

def vault(request):
    return render(request,"vault.html")

def tools(request):
    return render(request,"tools.html")

def encrypt_data(request):
    result_text="Cipher Text : "
    plain_text=request.POST['plain_text']
    key=request.POST['key']
    algorithm=int(request.POST['algorithm'])
    if(plain_text=="" and key==""):
        return render(request,"../templates/tools.html")
    else:
        if(algorithm==1):
            result_text+=sc.caesar_cipher(plain_text,int(key))
        elif(algorithm==2):
            result_text+=ra.rsa_algo(plain_text)
        elif(algorithm==3):
            result_text+=sa.swapping_encrypt(plain_text)
        else:
            pass
        context={
            'result_text':result_text
        }
        print(plain_text)
        print(key)
        print(algorithm)
        print(result_text)
        return render(request,"../templates/tools.html",context)