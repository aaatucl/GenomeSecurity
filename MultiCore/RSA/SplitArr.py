import allel
import hashlib
import Crypto
import os
import time
from Crypto.PublicKey import RSA
from hashlib import sha512
from hashlib import sha256
import pickle
import numpy as np
from numpy import savetxt
from numpy import loadtxt
import sys
import timeit
from os import urandom
from hashlib import sha256
from multiprocessing import Process
import multiprocessing
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

VCFfilePath = sys.argv[1]
Segments = int(sys.argv[2])

def save_key(private_key, filename):
    pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption())
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

def load_key(filename):
    with open(filename, 'rb') as key_file:
        #pemlines = pem_in.read()
    	private_key = serialization.load_pem_private_key(key_file.read(), password=None,)
    return private_key

def SaveArr(fname, SegArr):
	file = open(fname, "wb")
	return np.save(file, SegArr)

def OpenArr(fname):
	file = open(fname, "rb")
	return np.load(file, allow_pickle = True)

def EncodeArr(Arr):
	SegmentedVariantsArrEncoded = []
	for x in Arr:
		SegmentedVariantsArrEncoded.append(str(x).encode())
	return SegmentedVariantsArrEncoded

def OpenVCFfileAsArray(fpath):
	VariantsArr = allel.vcf_to_recarray(fpath)
	return VariantsArr

def SegmentArr(Arr, segs):
	SegmentedsArr = np.array_split(Arr, int(segs))
	return SegmentedsArr

def divide_chunks(l, n): 
      
    # looping till length l 
    for i in range(0, len(l), n):  
        yield l[i:i + n] 

VCF = OpenVCFfileAsArray(VCFfilePath)
#print(VCF)
VCF = SegmentArr(VCF, Segments)
VCF = EncodeArr(VCF)



div = int((Segments/32) + 1)
print ("div: ",div)
VCF = list(divide_chunks(VCF, div))


print(len(VCF))
n = 1
for portion in VCF:
	ArrName = "Arr"+str(n)
	SaveArr(ArrName,portion)
	n = n+1