# based on code https://asecuritysite.com/encryption/ped
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
from Crypto import *
from Crypto import Random
from Crypto import Util as Cutil
from numba import jit




bits = sys.argv[1]
resultfile = "MHTexperimentResults18Nov" + bits + "bits1" 
commitmentsfile = "commitments18Nov" + bits + "bits1" 

mt = MerkleTools()
RSAbitsNum = 2048
hash_type = "sha256" 
ra = allel.vcf_to_recarray('../files/NB72462M.vcf')
ExperimentResults = open(resultfile, "w")
RootSigFile = "root_sig"
CommitmentsFileName = commitmentsfile
TreeName = "mtlevels"
commitments = [[],[]]
lvs = []



def strlvs():
	for x in ra:
 		lvs.append(str(x))
strlvs()


hash_function = getattr(hashlib, hash_type)


def GenerateMHT(leavess):
	global keyPair
	global mt
	global RootSigFile
	global salts
	global lvs
	root_hash = []
	root_signature = []
	SaltedHashes = []
	for x in lvs:
		c_hash = sha256((x.encode())).hexdigest()

		c1, r1 = p.commit(param, int(c_hash,16)) 

		mt.add_leaf(str(c1),True)
		commitments[0].append(c1)
		commitments[1].append(r1)


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
        global commitments

        merkle_root = bytearray.fromhex(merkle_root)

        c_hash = sha256(((lvs[int(target_hash)]).encode())).hexdigest()

        if ((v.open(param, commitments[0][int(target_hash)],int(c_hash,16) , commitments[1][int(target_hash)])) == False):
        	print("Failed to verify: ", str(ra[int(target_hash)]))
        #else:
        #	print("v.open results is: ", v.open(param, commitments[0][int(target_hash)],int(c_hash,16) , commitments[1][int(target_hash)]))
        target_hash = commitments[0][int(target_hash)]
        target_hash = str(target_hash)
        target_hash =  target_hash.encode('utf-8')
        target_hash = hash_function(target_hash).hexdigest()
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


def generate(param):
        q = param[1]
        g = param[2]
        h = param[3]
        return q,g,h

class verifier:
    def setup(self, security):
        p = Cutil.number.getPrime(security, Random.new().read)
        q = Cutil.number.getPrime(160, Random.new().read)


        g = Cutil.number.getRandomRange(1, q-1)
        s = Cutil.number.getRandomRange(1, q-1)
        print("Secret value:\t",s)
        h = pow(g,s,q)
        
        param = (p,q,g,h)
        print("p=",p)
        print("q=",q)
        print("g=",g)
        print("h=",h)

        return param

    def open(self, param, c, x, *r):
        result = "False"
        q,g,h = generate(param)

        sum = 0
        for i in r:
            sum += i

        res = (pow(g,x,q) * pow(h,sum,q)) % q

        if(c == res):
            result = "True"
        return result  

    def add(self, param, *cm):
        addCM = 1
        for x in cm:
            addCM *= x
        addCM = addCM % param[1]
        return addCM
        
class prover: 
    def commit(self, param, x):
        q,g,h = generate(param)
        
        r = Cutil.number.getRandomRange(1, q-1)
        c = (pow(g,x,q) * pow(h,r,q)) % q
        return c, r
    

v = verifier()
p = prover()
param = v.setup(int(bits))
keyPair = GenerateRSAkeys(int(RSAbitsNum))
SaveMyRSAKey(keyPair,'mykey.pem')
key = LoadMyRSAkey('mykey.pem')
print("Priv Key is", key.exportKey())



TimeToGenerateMHT = timeit.timeit('GenerateMHT(ra)','from __main__ import GenerateMHT, ra', number=1)
print("the time it took ToGenerateMHT", TimeToGenerateMHT)

mtlevels = mt.levels

TimeToSaveMHT = timeit.timeit('SaveRootSignature(TreeName, mtlevels)','from __main__ import SaveRootSignature, TreeName, mtlevels', number=1)
print("the time it took to save tree levels", TimeToSaveMHT)

TimeToSaveCommitments = timeit.timeit('SaveRootSignature(CommitmentsFileName, commitments)','from __main__ import SaveRootSignature, CommitmentsFileName, commitments', number=1)
print("the time it took to save Commitments", TimeToSaveCommitments)

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
ExperimentResults.write("The time it took to save Commitments is " + str(TimeToSaveCommitments) + " seconds\n")
CommitmentsFileSize = os.path.getsize(CommitmentsFileName)/(1024)
ExperimentResults.write("The Size of saved commitments is " + str(CommitmentsFileSize) + "\n")
ExperimentResults.write("The time it took to save tree levels is " + str(TimeToSaveMHT) + " seconds\n")
MHTFileSize = os.path.getsize(TreeName)/(1024)
ExperimentResults.write("The Size of saved tree levels is " + str(MHTFileSize) + "\n")
ExperimentResults.write("The time it took to validate one variant in MHT " + str(TimeTovalidateMHT) + " seconds\n")
ExperimentResults.write("The time it took to validate 10000 variant in MHT " + str(TimeTovalidateMHTmany0) + " seconds\n")
ExperimentResults.write("The time it took to validate 100000 variant in MHT " + str(TimeTovalidateMHTmany) + " seconds\n")
ExperimentResults.write("The time it took to validate 1000000 variant in MHT " + str(TimeTovalidateMHTmany1) + " seconds\n")
ExperimentResults.write("The time it took to validate 4975892 variant in MHT " + str(TimeTovalidateMHTmany2) + " seconds\n")


