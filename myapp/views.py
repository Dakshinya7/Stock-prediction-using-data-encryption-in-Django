import pandas as pd
from Crypto.Util.Padding import pad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from joblib import load
from .models import LoginData, InputData
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.contrib import messages
import pickle
import sklearn
# Create your views here.

def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(data, cipher.algorithm.block_size)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data


def home(request):
    # Load the encrypted dataset
    encrypted_dataset_path = "C:/Users/91934/OneDrive/Desktop/Deepthitha/DSA_Project/Data/stock-encryptednewdata.csv"
    encrypted_df = pd.read_csv(encrypted_dataset_path)

    if request.method == 'POST':
        # Retrieve input values for all 10 features
        OperatingMargin = float(request.POST['OperatingMargin'])
        NetIncome = float(request.POST['NetIncome'])
        NetIncomeApplicableToCommonShareholders = float(request.POST['NetIncomeApplicableToCommonShareholders'])
        NonRecurringItems = float(request.POST['NonRecurringItems'])
        PreTaxMargin = float(request.POST['PreTaxMargin'])
        ProfitMargin = float(request.POST['ProfitMargin'])
        NetIncomeContOperations = float(request.POST['NetIncomeContOperations'])
        OperatingIncome = float(request.POST['OperatingIncome'])
        EarningsBeforeTax = float(request.POST['EarningsBeforeTax'])
        EarningsBeforeInterestAndTax = float(request.POST['EarningsBeforeInterestAndTax'])

        # Create a dictionary with input values
        input_data_dict = {
            'OperatingMargin': OperatingMargin,
            'NetIncome': NetIncome,
            'NetIncomeApplicableToCommonShareholders': NetIncomeApplicableToCommonShareholders,
            'NonRecurringItems': NonRecurringItems,
            'PreTaxMargin': PreTaxMargin,
            'ProfitMargin': ProfitMargin,
            'NetIncomeContOperations': NetIncomeContOperations,
            'OperatingIncome': OperatingIncome,
            'EarningsBeforeTax': EarningsBeforeTax,
            'EarningsBeforeInterestAndTax': EarningsBeforeInterestAndTax
        }

        # Convert the dictionary to a DataFrame
        input_df = pd.DataFrame([input_data_dict])

        # Load the model
        clf = load("C:/Users/91934/OneDrive/Desktop/Deepthitha/DSA-CAT-1/stockpredict/Model/SFM2.joblib")

        # Make predictions
        result = clf.predict(input_df)

        # Save input data and result
        InputData.objects.create(input_data=encrypt_data(input_df.to_csv(index=False).encode('utf-8'), b'securitykeyyazhi'), result=float(result))

        # Display the result on the webpage
        messages.success(request, f"Prediction result: {result}")

    return render(request, 'C:/Users/91934/OneDrive/Desktop/Deepthitha/DSA-CAT-1/stockpredict/myapp/template/myapp/home.html')

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Log in the user and redirect to the home page
            django_login(request, user)
            return HttpResponseRedirect('/home/')
        else:
            # Return an invalid login message or redirect to the login page
            messages.error(request, 'Invalid login credentials. Please try again.')

    return render(request, 'C:/Users/91934/OneDrive/Desktop/Deepthitha/DSA-CAT-1/stockpredict/myapp/template/myapp/login.html')

def logout(request):
    # Log out the user
    django_logout(request)
    return HttpResponseRedirect('/login/')