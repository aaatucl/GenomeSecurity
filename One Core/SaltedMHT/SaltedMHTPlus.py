from merkletools import MerkleTools
import allel
import numpy as np
import hashlib
import binascii
import sys
import timeit
import os
from Crypto.PublicKey import RSA
from hashlib import sha512
from hashlib import sha256
import hmac
from fastpbkdf2 import pbkdf2_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from cryptography.hazmat.primitives import hashes


#size = sys.getsizeof(str(salt))



mt = MerkleTools()
RSAbitsNum = 2048
hash_type = "sha256" 
ra = allel.vcf_to_recarray('../files/NB72462M.vcf')
Iter = int(sys.argv[1])
ResiltFileName = "MHTexperimentResults1IterNov11PBKDF2HMAC256Iter" + str(Iter)
ExperimentResults = open(ResiltFileName, "w")
RootSigFile = "root_sig"
SaltsFileName = "salts"
TreeName = "mtlevels"
salts = []
lvs = []
for x in ra:
 	lvs.append(str(x))



hash_function = getattr(hashlib, hash_type)

def GenerateMHT(leavess):
	global keyPair
	global mt
	global RootSigFile
	global salts
	global lvs
	global Iter
	root_hash = []
	root_signature = []
	SaltedHashes = []
	tmplvs = []
	for x in lvs:
		#print(x)
		salt = os.urandom(64)
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32, salt=salt,iterations=Iter)
		key = kdf.derive(x.encode())
		key = base64.urlsafe_b64encode(key).hex()
		#w = w.hexdigest()
		#print(w)
		tmplvs.append(key)
		#print("s_hash",s_hash)
		#s_hash = s_hash.hex()
		#print("s_hash.hex()", s_hash)
		#print("str(s_hash)", str(s_hash))
		salts.append(salt)
	mt.add_leaf(tmplvs)

	#for x in leavess:
	#	mt.add_leaf(str(x),True)
	mt.make_tree()
	root =  mt.get_merkle_root()
	
	root_hash.append(int.from_bytes(sha256((str(root).encode())).digest(), byteorder='big'))
	print("root_hash",root_hash)
	root_signature.append(pow(root_hash[0], keyPair.d, keyPair.n))
	print("root_signature", root_signature)
	SaveRootSignature(RootSigFile, root_signature)
	


def GenerateRSAkeys(bitsNum):
	return RSA.generate(bits=bitsNum)

def SaveMyRSAKey(keyPair, fname):
	f = open(fname,'wb')
	f.write(keyPair.export_key('PEM'))

def LoadMyRSAkey(fname):
	f = open(fname,'r')
	return RSA.import_key(f.read())

def SaveRootSignature(fname, SegArr):
	file = open(fname, "wb")
	np.save(file, SegArr)

def LoadRootSignature(fname):
	file = open(fname, "rb")
	return np.load(file, allow_pickle = True)

def to_hex(x):

	try:
		return x.hex()
	except:
		return binascii.hexlify(x)

def GetTheProof(levels, index):
	proof = []
	for x in range(len(levels) - 1, 0, -1):
		level_len = len(levels[x])
		if (index == level_len - 1) and (level_len % 2 == 1):  # skip if this is an odd end node
			index = int(index / 2.)
			continue
		is_right_node = index % 2
		sibling_index = index - 1 if is_right_node else index + 1
		sibling_pos = "left" if is_right_node else "right"
		sibling_value = to_hex(levels[x][sibling_index])
		proof.append({sibling_pos: sibling_value})
		index = int(index / 2.)
	return proof

def get_merkle_root(levels):
	return to_hex(levels[0][0])

def get_leaf(leaves, index):
	v = str(leaves[index])
	v = v.encode('utf-8')
	v = hash_function(v).hexdigest()
	v = bytearray.fromhex(v)
	return to_hex(v)

def validate_proof(proof, target_hash, merkle_root):
        global lvs
        global Iter
        merkle_root = bytearray.fromhex(merkle_root)
        th = int(target_hash)
        #target_hash = pbkdf2_hmac('sha256', lvs[target_hash].encode(), salts[target_hash], Iter)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32, salt=salts[target_hash],iterations=Iter)
        key = kdf.derive(lvs[target_hash].encode())
        target_hash = base64.urlsafe_b64encode(key).hex()
        target_hash = bytearray.fromhex(target_hash)

        if len(proof) == 0:
            return target_hash == merkle_root
        else:
            proof_hash = target_hash
            for p in proof:
                try:
                    # the sibling is a left node
                    sibling = bytearray.fromhex(p['left'])
                    proof_hash = hash_function(sibling + proof_hash).digest()
                except:
                    # the sibling is a right node
                    sibling = bytearray.fromhex(p['right'])
                    proof_hash = hash_function(proof_hash + sibling).digest()
            #print(proof_hash == merkle_root)
            return proof_hash == merkle_root

def validate_n_varaints(n,tree,arr):
	global ExperimentResults
	keyPair = LoadMyRSAkey('mykey.pem')
	root_signature = LoadRootSignature(RootSigFile)
	print("loaded root sign", root_signature)
	root = get_merkle_root(tree)
	root_hash = int.from_bytes(sha256((str(root).encode())).digest(), byteorder='big')
	verify = pow(root_signature[0], keyPair.e, keyPair.n)

	print("verify", verify)
	print("verify: ", verify == root_hash)
	for x in range(n):

		z = validate_proof(GetTheProof(tree,x), x, get_merkle_root(tree))
		if (z == False):
			ExperimentResults.write("The proof of " + str(x) + " is False\n")




keyPair = GenerateRSAkeys(int(RSAbitsNum))
SaveMyRSAKey(keyPair,'mykey.pem')
key = LoadMyRSAkey('mykey.pem')
print("Priv Key is", key.exportKey())



TimeToGenerateMHT = timeit.timeit('GenerateMHT(ra)','from __main__ import GenerateMHT, ra', number=1)
print("the time it took ToGenerateMHT", TimeToGenerateMHT)

mtlevels = mt.levels

TimeToSaveMHT = timeit.timeit('SaveRootSignature(TreeName, mtlevels)','from __main__ import SaveRootSignature, TreeName, mtlevels', number=1)
print("the time it took to save tree levels", TimeToSaveMHT)

TimeToSaveSalts = timeit.timeit('SaveRootSignature(SaltsFileName, salts)','from __main__ import SaveRootSignature, SaltsFileName, salts', number=1)
print("the time it took to save salts", TimeToSaveSalts)

NewAuthPath = LoadRootSignature(TreeName)

TimeTovalidateMHT = timeit.timeit('validate_proof(GetTheProof(NewAuthPath,2), 2, get_merkle_root(NewAuthPath))','from __main__ import validate_proof, GetTheProof, get_leaf, get_merkle_root, NewAuthPath, ra', number=1)
print("he time it took to validate one variant in MHT", TimeTovalidateMHT)

TimeTovalidateMHTmany0 = timeit.timeit('validate_n_varaints(10000,NewAuthPath,ra)','from __main__ import validate_n_varaints, NewAuthPath, ra', number=1)
print("The time it took to validate 10000 variant in MHT", TimeTovalidateMHTmany0)
TimeTovalidateMHTmany = timeit.timeit('validate_n_varaints(100000,NewAuthPath,ra)','from __main__ import validate_n_varaints, NewAuthPath, ra', number=1)
print("The time it took to validate 100000 variant in MHT", TimeTovalidateMHTmany)
TimeTovalidateMHTmany1 = timeit.timeit('validate_n_varaints(1000000,NewAuthPath,ra)','from __main__ import validate_n_varaints, NewAuthPath, ra', number=1)
print("The time it took to validate 1000000 variant in MHT", TimeTovalidateMHTmany1)
TimeTovalidateMHTmany2 = timeit.timeit('validate_n_varaints(4975892,NewAuthPath,ra)','from __main__ import validate_n_varaints, NewAuthPath, ra', number=1)
print("The time it took to validate 4975892 variant in MHT", TimeTovalidateMHTmany2)

ExperimentResults.write("The time it took to Generate MHT: " + str(TimeToGenerateMHT) + " seconds\n")
ExperimentResults.write("The time it took to save salts is " + str(TimeToSaveSalts) + " seconds\n")
SaltsFileSize = os.path.getsize(SaltsFileName)/(1024)
ExperimentResults.write("The Size of saved salts is " + str(SaltsFileSize) + "\n")
ExperimentResults.write("The time it took to save tree levels is " + str(TimeToSaveMHT) + " seconds\n")
MHTFileSize = os.path.getsize(TreeName)/(1024)
ExperimentResults.write("The Size of saved tree levels is " + str(MHTFileSize) + "\n")
ExperimentResults.write("The time it took to validate one variant in MHT " + str(TimeTovalidateMHT) + " seconds\n")
ExperimentResults.write("The time it took to validate 10000 variant in MHT " + str(TimeTovalidateMHTmany0) + " seconds\n")
ExperimentResults.write("The time it took to validate 100000 variant in MHT " + str(TimeTovalidateMHTmany) + " seconds\n")
ExperimentResults.write("The time it took to validate 1000000 variant in MHT " + str(TimeTovalidateMHTmany1) + " seconds\n")
ExperimentResults.write("The time it took to validate 4975892 variant in MHT " + str(TimeTovalidateMHTmany2) + " seconds\n")


