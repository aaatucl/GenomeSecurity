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

#VCFfilePath = sys.argv[1]
# print(VCFfilePath)
bits = sys.argv[1]
# print(bits)

ExperimentResultsFileName = sys.argv[2]

mul = int(sys.argv[3])

ExperimentResults = open(ExperimentResultsFileName, "w")

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



def SignitMulti(pos):
	print("pos: ", pos)

	key = load_key("mykey")
	ArrName = "Arr"+str(pos)
	Arr = OpenArr(ArrName)
	signatures = []
	for x in Arr:
		#print("x in Arr at SignitMulti", x)
		sss = key.sign(x,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
		signatures.append(sss)
	print("len(signatures)", len(signatures))
	SigsName = "Sigs" + str(pos)
	SaveArr(SigsName,signatures)

def VerifyitMulti(pos):
	print("pos: ", pos)
	key = load_key("mykey")
	SigsName = "Sigs" + str(pos)
	Sigs = OpenArr(SigsName)
	ArrName = "Arr"+ str(pos)
	Arr = OpenArr(ArrName)
	public_key = key.public_key()
	num = 0
	fail = 0
	for a, b in zip(Sigs, Arr):
		try:
			public_key.verify(a,b, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
			#print ("The signature is valid." + str(pos) + " " + str(num))
			num = num + 1
		except:
			#(ValueError, TypeError)
			#print ("The signature is not valid.")
			fail = fail + 1
			#print(str(pos) + " " + str(num))
			#print("----------------------------------------------------")
			pass
	#print("Total fail in " + str(pos) + " is " + str(fail))

def MultiSign():
	global mul
	global bits
	global key

	jobs = []
	for x in range(1, mul):
		print(x)
		p = Process(target=SignitMulti, args=(x,))
		p.start()
		jobs.append(p)

	for proc in jobs:
	        proc.join()

def MultiVerify():
	global mul 

	jobs = []
	for x in range(1, mul):
		print(x)
		p = Process(target=VerifyitMulti, args=(x,))
		p.start()
		jobs.append(p)

	for proc in jobs:
	        proc.join()
if __name__ == '__main__':
	key = rsa.generate_private_key(public_exponent=3,key_size=int(bits))
	save_key(key, "mykey")
	TimeToSign = timeit.timeit('MultiSign()','from __main__ import MultiSign', number=1)
	print("the time it took to excute MultiSign is", TimeToSign)


	TimeToVerify = timeit.timeit('MultiVerify()','from __main__ import MultiVerify', number=1)
	print("the time it took to excute MultiVerify is", TimeToVerify)

	ExperimentResults.write("the time it took to sign each segments is " + str(TimeToSign) + "\n")
	ExperimentResults.write("the time it took to vailidate each segments is " + str(TimeToVerify) + "\n")




