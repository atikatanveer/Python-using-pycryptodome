import time
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import strxor
import time

# PUF simulation using a hash function
def puf_simulation(input_data):
    h = SHA256.new()
    h.update(input_data.encode('utf-8'))
    return h.hexdigest()

# Hash function
def hash_data(data):
    h = SHA256.new()
    h.update(data.encode('utf-8'))
    return h.hexdigest()

# XOR function
def hexxor(a, b):    # xor two hex strings of the same length
    return "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(a, b)])
    

# database simulation
bc_database = {}
user_memory = {}
sd_memory = {}

# User Entity Registration
def SD_compute(IDsd):
   
    PIDsd = hash_data(IDsd)
    
    PKsd = puf_simulation(PIDsd)
   

    return PIDsd, PKsd



def server(PIDu, PPIDsd, PKsd):
    
    # Check if PIDu is already assigned
    if PIDu in bc_database:
        raise ValueError("PIDu already assigned, select a new identity")
        
    # Generate random number ru
    ru = get_random_bytes(16)
   
    PKu = hash_data(PIDu + ru.hex())
    
   
    Vbc_u = hash_data(Kbc + ru.hex())
   
    
    # Compute PPIDu
    PPIDu = hexxor(PKu, PIDu)
    PPIDu = hexxor(PPIDu, Vbc_u)
 
    # Store data in the blockchain server database
    bc_database[PKu] = {
        'PKu': PKu,
        'PIDu': PIDu,
        'PPIDu': PPIDu,
        'Vbc_u': Vbc_u
    }

     # Check if PKsd and PIDsd are already assigned
    if any(PIDsd in entry or PKsd in entry for entry in bc_database.values()):
        raise ValueError("PKsd and PIDsd already assigned, select a new identity")
    
    # Generate random number rsd
    rsd = get_random_bytes(16)
    
    # Extract Vbc-sd
   
    Vbc_sd = hash_data(Kbc + rsd.hex())
   
  
  
  
    # Compute PPIDsd
    PPIDsd = hexxor(PKsd, PIDsd)
    PPIDsd = hexxor(PPIDsd, Vbc_sd)
 
    bc_database[PKsd] = {
        'PKsd': PKsd,
        'PIDsd':PIDsd,
        'PPIDsd':PPIDsd,
        'Vbc_sd':Vbc_sd
        }
  
    # Publish PKu and send PKu and PPIDu to the user
    return PKu,PPIDu, PPIDsd, bc_database
    
def server_return_to_user(PKu, PPIDu):
    MAu = hexxor(PKu, IDu)
   
    MBu = hexxor(PPIDu, puf_simulation(IDu + Bu))
  
    
  
    Ru = puf_simulation(hexxor(PPIDu, hash_data(PWu)))
  
    
    
  
    Authu = hash_data(Ru + Bu + PKu)
   
    
    user_memory = {
        'MAu':MAu,
        'MBu':MBu,
        'Ru':Ru,
        'Authu':Authu
    }
   
    return user_memory
    


    
def server_return_to_sd(PPIDsd):
    
    Rsd = puf_simulation(PIDsd + IDsd)
   
    
    Asd = hexxor(PPIDsd,  Rsd)
    
    # Store computed value in local memory
    sd_memory = {
        'Asd': Asd
    }
    return sd_memory
    
##############################################################
#Authentication    
    
def user_bcs(user_memory):
   
    PIDu = puf_simulation(IDu + Bu)
   
    
    MAu = user_memory['MAu']
    MBu = user_memory["MBu"]
    Authu = user_memory["Authu"]
    PKu = hexxor(MAu, IDu)
    PPIDu = hexxor(MBu, PIDu)
    
   
    Ru = puf_simulation(hexxor(PPIDu, hash_data(PWu)))
   
    
    
    
  
    if Authu != hash_data(Ru + Bu + PKu):
        raise ValueError("Authentication failed")
    
    n1 = get_random_bytes(32)
  
    T1 = int(time.time())
    
    C1 = hexxor(n1.hex(), PIDu)
    C2 = hexxor(hexxor(PKu, PIDu), PPIDu)
    
    V1 = hexxor(n1.hex(), PKsd)
 
   
    V2 = hash_data(C2 + PIDu + PPIDu + PKu + str(T1))
  
    
    return C1, PKu, V1, V2, T1, C2, n1

def Auth_server1(C1, PKu, V1, V2, T1, bc_database):
    T2 = int(time.time())
    if abs(T2 - T1) > 5:
        raise ValueError("Request timed out")
        
   #scans the database for PKu and retrieves PIDu, PPIDu, and Vbc−u
    PIDu = ""
    PPIDu = ""
    Vbc_u = ""
    
    for key, value in bc_database.items():
        if value['PKu'] == PKu:
            PIDu = value['PIDu']
            PPIDu = value['PPIDu']
            Vbc_u = value['Vbc_u']
            break
   
    if not PIDu or V2 != hash_data(Vbc_u + PIDu + PPIDu + PKu + str(T1)):
        raise ValueError("Verification failed")
   
    print("User Authenticated")
 
    n1 = hexxor(C1, PIDu)
    
    PKsd = hexxor(n1, V1)

  # checks PKsd in the database and retrieves PIDsd, PPIDsd, Vbc−sd
    PIDsd = ""
    PPIDsd = ""
    Vbc_sd = ""
    
    for key, value in bc_database.items():
  
        if value.get('PKsd') == PKsd:
            PIDsd = value['PIDsd']
            PPIDsd = value['PPIDsd']
            Vbc_sd = value['Vbc_sd']
            break
    
    n2 = get_random_bytes(32)
    
 
    C3 = hexxor(n2.hex(), PPIDsd)
    C4 = hexxor(PKu, PIDsd)
    C4 = hexxor(C4, n2.hex())
   
    V3 = hexxor(hash_data(PIDu + PPIDu + n1), n2.hex())
   
    
  
    V4 = hash_data(Vbc_sd + C3 + C4 + PKu + n2.hex() + str(T2))
   
    
    return C3, C4, V3, V4, T2, n2, Vbc_u
    
    #####################################################
def Auth_server2(L1, T3, n2, Vbc_u):
    T4 = int(time.time())
    if abs(T4 - T3) > 5:
        raise ValueError("Request timed out")
    
    n3 = get_random_bytes(16)
    
   
    V5 = hexxor(n3.hex(), PPIDu)
   
    V6 = hexxor(n3.hex(), hash_data(PIDsd + PPIDsd + n2.hex()))
   
    
    
  
    L2 = hash_data(V5 + V6 + L1 + str(T1) + str(T3) + str(T4) + Vbc_u)
   
    
    return V5, V6, L1, L2, T3, T4
    
def auth_sd(C3, C4, V3, V4, T2, sd_memory):
    T3 = int(time.time())
    if abs(T3 - T2) > 5:
       raise ValueError("Request timed out")
       
    Asd = sd_memory['Asd']
  
    PIDsd = hash_data(IDsd)
    
    Rsd = puf_simulation(PIDsd + IDsd )
   
 
    PPIDsd = hexxor(Asd, Rsd)
    n2 = hexxor(PPIDsd, C3)
    PKu = hexxor(hexxor(C4, n2), PIDsd)
    
    
   
    if V4 != hash_data(hexxor(hexxor(PKsd, PIDsd), PPIDsd) + C3 + C4 + PKu + n2 + str(T2)):
        raise ValueError("Verification failed")
    
    print("Server Authenticated")    

    X = hexxor(V3,n2)   

    SK = hash_data(X + hash_data(PIDsd + PPIDsd + n2) + str(T3))
    
    L1 = hash_data(SK + PKu + PKsd + str(T3))
   
 
    return L1, T3
    
    
def user_receive_from_bcs(V5, V6, L1, L2, T3, T4, C2,n1):
    T5 = int(time.time())
    if abs(T5 - T4) > 5:
        raise ValueError("Request timed out")
  
    n3 = hexxor(PPIDu, V5)
   
    Y = hash_data(PIDsd + PPIDsd + n2.hex())
   
    

    if L2 != hash_data(V5 + V6 + L1 + str(T1) + str(T3) + str(T4) + C2):
        raise ValueError("Mutual authentication failed")
   
    print("Smart Device Authenticated")
    
    
  
    SK = hash_data(hash_data(PIDu + PPIDu + n1.hex()) + Y + str(T3))
   
    
  
    if L1 != hash_data(SK + PKu + PKsd + str(T3)):
        raise ValueError("validity of SK failed")
    
    print("Successfully secret keys shared between devices")
    return 0
    
##################################################################    
    
#MAIN
start_time = time.time()
IDu = input("Enter your ID: ")
#IDu = "UserID"
PWu = input("Enter your password: ")
#PWu = "atika123"
Bu = input("Enter your Biometrics: ")
#Bu = "ati"
Kbc ="123"
IDsd = "SmartDeviceID"



IDsd = hash_data(IDsd)





IDu = hash_data(IDu)



# User 

PIDu = puf_simulation(IDu + Bu)

PIDsd, PKsd = SD_compute(IDsd)

PKu,PPIDu, PPIDsd, bc_database =server(PIDu, PIDsd, PKsd)

user_memory= server_return_to_user(PKu, PPIDu)

#Smart Device


sd_memory= server_return_to_sd(PPIDsd)

#Authentication
C1, PKu, V1, V2, T1, C2, n1= user_bcs(user_memory)

C3, C4, V3, V4, T2, n2, Vbc_u= Auth_server1(C1, PKu, V1, V2, T1, bc_database)
L1, T3 = auth_sd(C3, C4, V3, V4, T2, sd_memory)
V5, V6, L1, L2, T3, T4= Auth_server2( L1, T3, n2, Vbc_u)

user_receive_from_bcs(V5, V6, L1, L2, T3, T4, C2, n1)

