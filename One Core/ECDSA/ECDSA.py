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
from petlib.cipher import Cipher
from petlib.bn import Bn
from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify, do_ecdsa_setup


VCFfilePath = sys.argv[1]
print(VCFfilePath)
SigsFileName = sys.argv[2]
print(SigsFileName)
HashType = sys.argv[3]
print(HashType)

Segments = sys.argv[4]
print(Segments)
ExperimentResultsFileName = sys.argv[5]
ExperimentResults = open(ExperimentResultsFileName, "w")

ArrFileName = "ArrSeg" + Segments
print ("ArrFileName", ArrFileName)

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
	return RSA.generate(bits=bitsNum)

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
			digest = sha256(x).digest()
			hashes.append(digest)
	elif (shatype == 'sha384'):
		for x in VariantsArr:
			hashes.append(int.from_bytes(sha384(x).digest(), byteorder='big'))
	elif (shatype == 'sha512'):
		for x in VariantsArr:
			hashes.append(int.from_bytes(sha512(x).digest(), byteorder='big'))
	
	return hashes

def GenerateSignturesOfHashes(hashes, Gx, priv_signx):
	signatures = []
	global kinv_rp
	for x in hashes:
		z = do_ecdsa_sign(Gx, priv_signx, x, kinv_rp = kinv_rp)
		signatures.append(z)
	return signatures
def SaveSignturesIntoFile(fname,sigs):
	s = []
	for x in sigs:
		s.append(str(x))
	file = open(fname, "wb")
	np.save(file, s)

def LoadSignturesFromFile(fname):
	file = open(fname, "rb")
	return np.load(file, allow_pickle = True)

def GethashedFromSignatures(sigs, keyPair):
	hashFromSignatures = []
	for x in sigs:
		digest = sha256(x).digest()
		hash.append(digest)
	return hashFromSignatures

def CompareHashesOfTwoArr(hashes,sigs,Gx ,pub_verifyx):
	failed = 0
	result = True
	for a, b in zip(hashes, sigs):
		res = do_ecdsa_verify(Gx, pub_verifyx, b, a)
		if (res == False):
			result = False
	return result


# ---------------------- Signing Phase --------------------------------- #

G = EcGroup(714)
print("G is: ",G)
priv_sign = G.order().random()
print("priv_sign: ", priv_sign)
kinv_rp = do_ecdsa_setup(G, priv_sign)
pub_verify = priv_sign * G.generator()
print("pub_verify: ", pub_verify)

VariantsArr = OpenVCFfileAsArray(VCFfilePath)
SegmentedVariantsArr = SegmentArr(VariantsArr, Segments)
SegmentedVariantsArrEncoded = EncodeArr(SegmentedVariantsArr)


signatures = []
def signit(Gx, priv_signx,pub_verifyx ,SigsFile, segs, VCFfilePath, HType, ArrFName):
	global signatures
	global SegmentedVariantsArrEncoded
	hashesToBeSigned = CreateHashListOfVariants(SegmentedVariantsArrEncoded, HType)
	print("len(hashesToBeSigned)", len(hashesToBeSigned))


	signatures = GenerateSignturesOfHashes(hashesToBeSigned, Gx, priv_signx)
	print("len(signatures)", len(signatures))
	


# ---------------------- Veryfication Phase --------------------------------- #

def VaildateSigntures(Gx, priv_signx,pub_verifyx, SigsFile, segs, VCFfilePath,HType):
	global signatures
	global SegmentedVariantsArrEncoded

	hashesToBeVerified = CreateHashListOfVariants(SegmentedVariantsArrEncoded, HType)
	print("len(hashesToBeVerified)", len(hashesToBeVerified))


	print("Signature valid:", CompareHashesOfTwoArr(hashesToBeVerified,signatures,Gx ,pub_verifyx))


TimeToSign = timeit.timeit('signit(G, priv_sign ,pub_verify, SigsFileName, Segments, VCFfilePath, HashType, ArrFileName)','from __main__ import signit, SigsFileName, Segments, VCFfilePath, HashType, ArrFileName, G, priv_sign ,pub_verify', number=1)
print("the time it took to excute signit is", TimeToSign)


TimeToVerify = timeit.timeit('VaildateSigntures(G, priv_sign,pub_verify, SigsFileName, Segments, VCFfilePath, HashType)','from __main__ import VaildateSigntures, SigsFileName, Segments, VCFfilePath, HashType,G, priv_sign ,pub_verify', number=1)
print("the time it took to excute VaildateSigntures is", TimeToVerify)

ExperimentResults.write("The time it took to excute signit is " + str(TimeToSign) + " seconds\n")
ExperimentResults.write("The time it took to excute VaildateSigntures is " + str(TimeToVerify) + " seconds\n")
