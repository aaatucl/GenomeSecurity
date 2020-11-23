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
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


VCFfilePath = sys.argv[1]
print(VCFfilePath)


def OpenVCFfileAsArray(fpath):
	VariantsArr = allel.vcf_to_recarray(fpath)
	return VariantsArr

def EncodeArr(Arr):
	SegmentedVariantsArrEncoded = []
	for x in Arr:
		SegmentedVariantsArrEncoded.append(str(x).encode())
	return SegmentedVariantsArrEncoded
def SegmentArr(Arr, segs):
	SegmentedsArr = np.array_split(Arr, int(segs))
	return SegmentedsArr
def SaveSegmentedVariantsArr(fname, SegArr):
	file = open(fname, "wb")
	np.save(file, SegArr)

def OpenSegmentedVariantsArr(fname):
	file = open(fname, "rb")
	return np.load(file, allow_pickle = True)

def GenerateRSAkeys(bitsNum):
	return RSA.generate(bits=bitsNum, e=3)

def SaveMyRSAKey(keyPair, fname):
	f = open(fname,'wb')
	f.write(keyPair.export_key('PEM'))

def LoadMyRSAkey(fname):
	f = open(fname,'r')
	return RSA.import_key(f.read())

def CreateHashListOfVariants(VariantsArr,shatype):
	hashes = []
	
	if (shatype == 'sha256'):
		for x in VariantsArr:
			hashes.append(SHA256.new(x))
	elif (shatype == 'sha384'):
		for x in VariantsArr:
			hashes.append(int.from_bytes(sha384(x).digest(), byteorder='big'))
	elif (shatype == 'sha512'):
		for x in VariantsArr:
			hashes.append(int.from_bytes(sha512(x).digest(), byteorder='big'))
	
	return hashes

def GenerateSignturesOfHashes(hashes, keyPair):
	signatures = []
	for x in hashes:
		#z = pow(x, keyPair.d, keyPair.n)
		z = pkcs1_15.new(keyPair).sign(x)
		signatures.append(z)
	return signatures
def SaveSignturesIntoFile(fname,sigs):
	file = open(fname, "wb")
	np.save(file, sigs)

def LoadSignturesFromFile(fname):
	file = open(fname, "rb")
	return np.load(file, allow_pickle = True)

def VerifyRSAsigs(sigs,hashesToBeVerified, keyPair):
	hashFromSignatures = []
	for a, b in zip(sigs, hashesToBeVerified):
		#hashFromSignatures.append(pow(x, keyPair.e, keyPair.n))
		try:
			pkcs1_15.new(keyPair).verify(b, a)
			print ("The signature is valid.")
		except (ValueError, TypeError):
			print ("The signature is not valid.")
	

def CompareHashesOfTwoArr(x,y):
	return x == y




def signit(key):
	global signatures
	global SegmentedVariantsArrEncoded

	for x in SegmentedVariantsArrEncoded:
		sss = key.sign(x,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
		signatures.append(sss)
	


# ---------------------- Veryfication Phase --------------------------------- #

def VaildateSigntures(key):
	global signatures
	global SegmentedVariantsArrEncoded

	public_key = key.public_key()
	for a, b in zip(signatures, SegmentedVariantsArrEncoded):
		try:
			public_key.verify(a,b, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
			#print ("The signature is valid.")
		except (ValueError, TypeError):
			print ("The signature is not valid.")
			print("----------------------------------------------------")

signatures = []
VariantsArr = OpenVCFfileAsArray(VCFfilePath)
Segments = ['1','100','10000','100000','1000000',str(len(VariantsArr))]
RSAbits = ['1024','2048','3072']
for seg in Segments:
	print("seg: ",seg)
	SegmentedVariantsArr = SegmentArr(VariantsArr, seg)
	SegmentedVariantsArrEncoded = EncodeArr(SegmentedVariantsArr)
	print("SegmentedVariantsArrEncoded:", len(SegmentedVariantsArrEncoded))
	for bits in RSAbits:
		key = rsa.generate_private_key(public_exponent=3,key_size=int(bits))
		ExperimentResultsFileName = 'ResultsSegs'+seg+'Bits'+bits
		print(ExperimentResultsFileName)
		ExperimentResults = open(ExperimentResultsFileName, "w")

		TimeToSign = timeit.timeit('signit(key)','from __main__ import signit, key', number=1)
		print("the time it took to excute signit is", TimeToSign)


		TimeToVerify = timeit.timeit('VaildateSigntures(key)','from __main__ import VaildateSigntures, key', number=1)
		print("the time it took to excute VaildateSigntures is", TimeToVerify)

		ExperimentResults.write("the time it took to excute signit is " + str(TimeToSign) + "\n")
		ExperimentResults.write("the time it took to excute VaildateSigntures is " + str(TimeToVerify) + "\n")
		signatures = []



