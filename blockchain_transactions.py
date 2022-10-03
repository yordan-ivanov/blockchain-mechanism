# Defining a transaction class for Zimcoin.
class Zimcoin_Transactions(object):
   
    """
    Blockchain Transactions for Humans:
    Class object that performs blockchain transactions. It does not take any initiation arguments. 
    The standard way of implementing the class object should include the class followed by one of the 
    method defined within it. See example below:
    
    Example:
    --------
    >>> Transaction = Zimcoin_Transactions() 
    >>> Transaction.Add_balance()
    >>> Transaction.Input()
    >>> Transaction.Output()
    
    >>> Transaction.Blocks(all)
    >>> Transaction.Blocks("balance_No") 

    
    Parameters:
    -----------
    1. All transaction amounts are in Zimcoins. 1 Zimcoin is the smallest unit of currency. 
       It is impossible to send someone a half Zimcoin.
    
    2. All public and private keys requiered from the inputs are in hexadecimals. 
       Do not type any other formats as it may raise an error.
    
    Methods:
    --------
    ___init__()
            Create class initiation for the class object.
            
    Blocks(feature)
            The method returns all the blockchain data or a particular attribute from it specified by the
            argument "feature". See example above.
            
    Update(data)
            The method updates and stores the blockchain data to a pickle file. 
            
            
    OP_fetch()
            The method is intended to find particular block and extract given feature from it.
            
    OP_locate()
            The method locate the index of a block with given value from a particular block feature.
            
    SHA1_hashing(private_key, public_key, amount, fee, nonce, timestamp, block_No)
            The method performs SHA1 encryption with the help of Cryptography.Hazmat.Primitives.
            The arguments required for the encryption are self explanatories.
            
    SHA256_hashing(data, salt, pepper)
            The method performs SHA256 encryption with the help of Cryptography.Hazmat.Primitives.
            The arguments required for the encryption are self the hashed data from the SHA1 method plus
            nonce assigned to each block transaction and the public key of the user.
            
    Sign_transaction(private_key, data)
            The method performs digital signature so as to confirm the transaction. It requires the 
            private key of the user and any hashed data.
            
    Add_balance()
            The method adds monetary value to a particular balance account from the blockchain.
            The method asks for the public key of the user and amount to be added to their balance number.
    
    Input()
            The method creates a transatian input to receive coins from a particular sender. The transaction
            stay unverified until the blockchain verification class is not performed.
    
    Output()
             The method defines a transaction output through sending coins from one blockchain public key to 
            another. The transaction is not verified until the blockchain verification class is not performed.  
            
    Error raised:
    -------------
    All public and private keys requiered from the inputs are in hexadecimals.
    If you type any other formats it will raise a ValueError: non-hexadecimal number found in fromhex() arg.
    
    If you enter a wrong private key encryption it will raise a ValueError: Could not deserialize key data. 
    The data may be in an incorrect format or it may be encrypted with an unsupported algorithm.
    
    """
    # Create class initiation.
    def __init__(self):
        self.fee = 0
        self.yes_list = ('yes', 'YES', 'Yes', 'y', 'yES', 'yeS', 'YEs', 'Y', 'yeah')
        
    # Defining a method to display all blocks or invoke a feature from the blockchain.   
    def Blocks(self, feature):
        if feature == all:
            print('\n\033[1m========================== Zimcoin Transactians ==========================\033[0m')
            for block in notebook.tqdm(pickle.load(open("./Data/Zimcoin_Transactions.pkl", 'rb')), desc='Loading Transactions'):
                print(f"\033[1m{block['trax_No']}\033[0m", block)
                print("\033[1m=====================================================================\033[0m\n")
        else:
            block_list = []
            for block in pickle.load(open("./Data/Zimcoin_Transactions.pkl", 'rb')):
                block_list.append(block[f'{feature}'])  
            return block_list
    
    # Method that saves transaction blocks as a pickle file.
    def Update(self, data):
        return pickle.dump(data, open("./Data/Zimcoin_Transactions.pkl", "wb"))
    
    # Defining a method that locate particular block and extract given feature from it.
    def OP_fetch(self, index, attribute):
        fetcher = pickle.load(open("./Data/Zimcoin_Transactions.pkl", 'rb'))
        return fetcher[index][f'{attribute}']
    
    # Defining a method that locate particular block and extract given feature from it.
    def OP_locate(self, attribute, value):
        blocks = pickle.load(open("./Data/Zimcoin_Transactions.pkl", 'rb'))
        temp_list = []
        for block in blocks:
            if block[f'{attribute}'] == value:
                temp_list.append(block['trax_No'])
            else:
                continue
        return int(temp_list[0])
    
    # Creating a method to digest transaction details.
    def SHA1_hashing(self, private_key, public_key, nonce, timestamp):
        digest = hashes.Hash(hashes.SHA1())
        digest.update(private_key)
        digest.update(public_key)
        digest.update(nonce)
        digest.update(timestamp)
        return digest.finalize()
    
    # Defining a method that hashes data.
    def SHA256_hashing(self, data, salt, pepper):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        digest.update(salt)
        digest.update(pepper)
        return digest.finalize()
    
    # Creating a method to sign a transaction.
    def Sign_transaction(self, private_key, data):
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature
        
    # Creating a method to add balance to the blockchain.
    def Add_balance(self):
        b = {}
        transactions = pickle.load(open("./Data/Zimcoin_Transactions.pkl", 'rb'))
        trax_No = transactions[-1]['trax_No']
        no_list = ['no', 'NO', 'No', 'nO', 'Nope']
        balanceNo_checker = self.Blocks('balance_No')
        actial_balance_ = 0
        b['trax_No'] = None
        b['hash'] = None
        b['previous_hash'] = "Genesis"
        print('\n\033[1m\n======================= Zimcoin Transactians =======================\033[0m')
        name = (input("Enter your name: "))
        
        public_key_balance = input(f"\nHi {name.upper()}! \nIf you have Zimcoin's balance account please\nenter your PUBLIC KEY, otherwise type NO:\n")
        
        if public_key_balance in no_list:
            private_key_backend = ec.generate_private_key(ec.SECP256K1())
            public_key_balance = private_key_backend.public_key().public_bytes(encoding=Encoding.DER, 
                                                          format=PublicFormat.SubjectPublicKeyInfo).hex()
            print("\n\033[1m=====================================================================\033[0m", 
              "\nYour private key will be revealed in a few seconds...",
              "\nPlease copy the string and paste it in a secure place.",
              "\nThis is your only key to unlock your balance.",
              "\033[1m\nDO NOT SHARE YOUR PRIVATE KEY WITH ANYONE!\033[0m")
            private_key_balance = private_key_backend.private_bytes(
                                              encoding=Encoding.DER,
                                              format=PrivateFormat.PKCS8,
                                              encryption_algorithm=BestAvailableEncryption(b'testpassword')).hex()
            time.sleep(5)
            print(f"\n\033[1mPRIVATE KEY:\033[0m", f"\n{private_key_balance}")
            print("\n\033[1m=====================================================================\033[0m")
            
        # Balance account verification for the receiver. Ivalid public keys are dismissed. 
        elif public_key_balance in balanceNo_checker:
            print("\033[1mYour balance number has been verified!\033[0m")
            print("\n\033[1m=====================================================================\033[0m")
            genesis_idx = self.OP_locate('balance_No', public_key_balance)
            actial_balance_ = self.OP_fetch(genesis_idx, 'zimcoins')      
            b['previous_hash'] = self.OP_fetch(genesis_idx, 'hash')
          
        else:
            try_again = input(f"{name.upper()}, you have not generated any transaction input! \nThe PUBLIC KEY you have typed is invalid. \nWould you like to try again? ")
            if try_again in self.yes_list:
                public_key_balance = input("Please enter your PUBLIC KEY again: ")
                if public_key_balance in balanceNo_checker:
                    print("\033[1mYour balance number has been verified!\033[0m")
                    print("\n\033[1m=====================================================================\033[0m")
                    genesis_idx = self.OP_locate('balance_No', public_key_balance)
                    actial_balance_ = self.OP_fetch(genesis_idx, 'zimcoins')      
                    b['previous_hash'] = self.OP_fetch(genesis_idx, 'hash')    
                else:
                    print("\n\033[1m=====================================================================\033[0m",
                          "\nSorry, the PUBLIC KEY you have typed is invalid. Have a nice day!!!")
                    return False, "transactian attempt!"
            else:
                print("\n\033[1m=====================================================================\033[0m",
                      f"\nOK, Have a nice day!!!")
                return False, "transactian attempt!"
        
        # Verifying loop for the amount added, no integers values are dismissed. 
        while True:
            amount_added = input("How much \033[1mZimcoins\033[0m would you like to add to your balance?\n")
            try:
                value = int(amount_added)
                if value > 0:
                    break
                else:
                    print("\n\033[1m '{input}'\033[0m is not valid amount! \nPlease try a positive integer number.".format(input=amount_added))
            except ValueError:
                print("\n\033[1m '{input}'\033[0m is not valid amount! \nPlease try a positive integer number.".format(input=amount_added))
        
        # Verifying loop for the bank details, no integers values are dismissed.
        while True:
            bank_details = input("Entar your Credit/Debit card number: \n(any positive integer number just for testing purposes)\n")
            try:
                value = int(bank_details)
                if value > 0:
                    break
                else:
                    print("Banking details invalid. Please enter any positive integer number. ".format(input=bank_details))

            except ValueError:
                print("Banking details invalid. Please enter any positive integer number. ")
          
        b['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f")
        b['balance_No'] = public_key_balance
        b['zimcoins'] = int(amount_added)
        b['fee'] = int(int(amount_added)*0.0001)
        nonce = int.from_bytes(os.urandom(8), byteorder='little')
        b['nonce'] = nonce
        b['state'] = 'Verified'
        
        print("\n\033[1mTransactian Details:\n====================\033[0m",
              f"\n{name.upper()}, you have just added ", f"\033[1m{amount_added} ",
              "Zimcoins\033[0m to your balance. \nThis is your public key for your account.",
              "\n\033[1mPLEASE NOTE IT DOWN AS IT IS YOUR ACCOUNT NUMBER! \n\nPUBLIC KEY:\033[0m",
              f"\n{public_key_balance}")
        print("\033[1m=====================================================================\033[0m")
        private_key_balance = input("\nTo \033[1mSIGN OUT\033[0m the deposit please enter you PRIVATE KEY:\n")
        
        # Data hashing, data signing of the transaction.
        data = self.SHA1_hashing(bytes.fromhex(private_key_balance), 
                                 bytes.fromhex(public_key_balance), 
                                 str(nonce).encode('utf-8'), 
                                 str(b['timestamp']).encode('utf-8'))
        
        data_added = self.SHA256_hashing(data, str(nonce).encode('utf-8'), bytes.fromhex(public_key_balance))
        b['hash'] = data_added.hex()
        data_signing = self.SHA256_hashing(bytes.fromhex(public_key_balance), bytes.fromhex(public_key_balance), 
                                           str(amount_added).encode('utf-8'))
        
        # Verification of signature and private key. Invalid private keys are dismissed.
        try:
            signed = self.Sign_transaction(
            load_der_private_key(bytes.fromhex(private_key_balance), password=b'testpassword'), data_signing)
            load_der_public_key(bytes.fromhex(public_key_balance)).verify(signed, data_signing, ec.ECDSA(hashes.SHA256()))
            print("\033[1mValid private key!\033[0m")
        except InvalidSignature:
            print("\033[1m=====================================================================\033[0m",
                  "\n\033[1mThe deposit has not been signed. Invalid PRIVATE KEY!\033[0m")
            return False, "transactian attempt!"
        
        # Printing out previous and actual balance. 
        print("\033[1m=====================================================================\033[0m",
               f"\n\nOK {name.upper()}, your deposit has been processed.\nPrevious balaces: ", f"{actial_balance_} Zimcoins.",
               f"\nActual balance:\033[1m {int(amount_added) + int(actial_balance_)} Zimcoins\033[0m.",
               "\n\033[1m=====================================================================\033[0m",
              "\nAll done! Your payment is in progress...",)
        
        # Storing the transaction on the blockchain.
        trax_No = trax_No+1
        b['trax_No'] = trax_No
        b['signature'] = signed.hex()
        b['status'] = 'Unspent'
        transactions.append(b)
        self.Update(transactions)
        
    # Defining a method to creat transaction input to the blockchain.   
    def Input(self):
        din = {}
        transactions = pickle.load(open("./Data/Zimcoin_Transactions.pkl", 'rb'))
        trax_No = transactions[-1]['trax_No']
        din['trax_No'] = None
        din['hash'] = None
        din['previous_hash'] = None
        actual_balance = 0
        no_list = ['no', 'NO', 'No', 'nO', 'Nope']
        balanceNo_checker = self.Blocks('balance_No')
        
        # Collecting several inputs to formalize a transaction. 
        print('\n\033[1m\n======================= Zimcoin Transactians =======================\033[0m')
        recipient_name = input("Enter your name: ")
        public_key_input = input(f"\nHi {recipient_name.upper()}! \nIf you have Zimcoin's balance account please\nenter your PUBLIC KEY, otherwise type NO:\n")
        
        if public_key_input in no_list:
            private_key_backend = ec.generate_private_key(ec.SECP256K1())
            public_key_input = private_key_backend.public_key().public_bytes(encoding=Encoding.DER, 
                                                            format=PublicFormat.SubjectPublicKeyInfo).hex()
            print("\n\033[1m=====================================================================\033[0m", 
              "\nYour private key will be revealed in a few seconds...",
              "\nPlease copy the string and paste it in a secure place.",
              "\nThis is your only key to unlock your balance.",
              "\033[1m\nDO NOT SHARE YOUR PRIVATE KEY WITH ANYONE!\033[0m")
            private_key_input = private_key_backend.private_bytes(
                                                   encoding=Encoding.DER,
                                                   format=PrivateFormat.PKCS8,
                                                   encryption_algorithm=BestAvailableEncryption(b'testpassword')).hex()
            time.sleep(5)
            print(f"\n\033[1mPRIVATE KEY:\033[0m", f"\n{private_key_input}")
            print("\n\033[1m=====================================================================\033[0m")
        
        # Balance account verification for the receiver. Ivalid public keys are dismissed. 
        elif public_key_input in balanceNo_checker:
            print("\033[1mYour balance number has been verified!\033[0m")
            print("\n\033[1m=====================================================================\033[0m")
            for block in transactions:
                if public_key_input == block['balance_No']:
                    actial_balance = block['zimcoins']
                else:
                    continue
                    
        else:
            try_again = input(f"{recipient_name.upper()}, you have not generated any transaction input! \nThe PUBLIC KEY you have typed is invalid. \nWould you like to try again? ")
            if try_again in self.yes_list:
                public_key_input = input("Please enter your PUBLIC KEY again: ")
                if public_key_input in balanceNo_checker:
                    print("\033[1mYour balance number has been verified!\033[0m")
                    print("\n\033[1m=====================================================================\033[0m")
                    for block in transactions:
                        if public_key_input == block['balance_No']:
                            actial_balance = block['zimcoins']
                        else:
                            continue     
                else:
                    print("\n\033[1m=====================================================================\033[0m",
                          "\nSorry, the PUBLIC KEY you have typed is invalid. Have a nice day!!!")
                    return False, "transactian attempt!"
            else:
                print("\n\033[1m=====================================================================\033[0m",
                      f"\nOK, Have a nice day!!!")
                return False, "transactian attempt!"
        
        # Balance account verification for the sender. Ivalid public keys are dismissed.    
        sender_public_key = input("Please enter PUBLIC KEY of the sender:\n")
        if sender_public_key in balanceNo_checker:
            print("\033[1mSender balance number has been verified!\033[0m")
            for block in transactions:
                if sender_public_key == block['balance_No'] and block['state'] == 'Verified':
                    din['previous_hash'] = block['hash']
                else:
                    continue
        else:
            print("\n\033[1m=====================================================================\033[0m")
            try_again = input(f"{recipient_name.upper()}, you have not generated any transaction input! \nThe PUBLIC KEY you have typed is invalid. \nWould you like to try again? ")
            if try_again in self.yes_list:
                sender_public_key = input("Please enter the PUBLIC KEY of the sender:\n")
                if sender_public_key in balanceNo_checker:
                    print("\033[1mSender balance number has been verified!\033[0m")
                    for block in transactions:
                        if sender_public_key == block['balance_No'] and block['state'] == 'Verified':
                            din['previous_hash'] = block['hash']
                        else:
                            continue
                else:
                    print("\n\033[1m=====================================================================\033[0m",
                          "\nSorry, the PUBLIC KEY you have typed is invalid. Have a nice day!!!")
                    return False, "transactian attempt!"
            else:
                print("\n\033[1m=====================================================================\033[0m",
                      "\nSorry, the PUBLIC KEY you have typed is invalid. Have a nice day!!!")
                return False, "transactian attempt!" 
        
        # Verifying loop for the amount received, no integers values are dismissed.    
        while True:
            amount_to_receive = input("\nHow much \033[1mZimcoins\033[0m do you expect to receive?\n")
            try:
                value = int(amount_to_receive)
                if value > 0:
                    break
                else:
                    print("\n\033[1m '{input}'\033[0m is not valid amount! \nPlease try a positive integer number.".format(input=amount_to_receive))
            except ValueError:
                print("\n\033[1m '{input}'\033[0m is not valid amount! \nPlease try a positive integer number.".format(input=amount_to_receive))          
        
        # Data collection and printing out transaction details.           
        nonce = int.from_bytes(os.urandom(8), byteorder='little')
        din['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f")
        din['balance_No'] = public_key_input
        din['zimcoins'] = int(amount_to_receive)
        din['fee'] = 0
        din['nonce'] = nonce
        din['state'] = 'Unverified'
        
        print("\n\033[1mTransactian Details:\n====================\033[0m",
              f"\n{recipient_name.upper()}, You will receive \033[1m{amount_to_receive} Zimcoins.\033[0m",
              "\nThis is your public key for your transaction.",
              "\n\033[1mPLEASE NOTE IT DOWN IF YOU HAVE NOT DONE IT YET AS IT IS YOUR ACCOUNT NUMBER! \n\nPUBLIC KEY:\033[0m",
              f"\n{public_key_input}", "\n\033[1m=====================================================================\033[0m")
        
        # Data hashing and data signing of the transaction input. 
        private_key_input = input("\nTo \033[1mSIGN OUT\033[0m the transaction input please enter you PRIVATE KEY:\n")
        data_in = self.SHA1_hashing(bytes.fromhex(private_key_input), 
                                    bytes.fromhex(public_key_input),  
                                    str(nonce).encode('utf-8'), 
                                    str(din['timestamp']).encode('utf-8'))
        
        h_in = self.SHA256_hashing(data_in, str(nonce).encode('utf-8'), bytes.fromhex(public_key_input)).hex()
        din['hash'] = h_in
        data_sign_in = self.SHA256_hashing(bytes.fromhex(public_key_input), bytes.fromhex(sender_public_key), 
                                           str(amount_to_receive).encode('utf-8'))
        
        # Verification of signature and private key. Invalid private keys are dismissed.
        try:
            signed_in = self.Sign_transaction(load_der_private_key(bytes.fromhex(private_key_input), password=b'testpassword'), data_sign_in)
            load_der_public_key(bytes.fromhex(public_key_input)).verify(signed_in, data_sign_in, ec.ECDSA(hashes.SHA256()))
            print("\033[1mValid private key!\033[0m")
        except InvalidSignature:
            print("\n\033[1m=====================================================================\033[0m",
                 "\n\033[1mThe input has not been signed. Invalid PRIVATE KEY!")
            return False, "transactian attempt!"
        
        # Printing out previous and actual balance for the recipient. 
        print("\033[1m=====================================================================\033[0m",
               f"\n\nOK {recipient_name.upper()}, your transaction input is in progress...\nPrevious balaces: ", f"{actual_balance} Zimcoins.",
               f"\nActual balance:\033[1m {int(actual_balance) + int(amount_to_receive)} Zimcoins\033[0m.",
               "\n\033[1m=====================================================================\033[0m",
              "\nThe input is UNVERIFIED until the corresponding output is confirmed by the blockchain.",)
        
        # Storing the transaction on the blockchain.
        trax_No = trax_No+1
        din['trax_No'] = trax_No
        din['signature'] = signed_in.hex()
        din['status'] = 'Expected'
        transactions.append(din)
        self.Update(transactions)
    
    # Defining a method to creat transaction output to the blockchain.
    def Output(self):
        dout = {}
        transactions = pickle.load(open("./Data/Zimcoin_Transactions.pkl", 'rb'))
        trax_No = transactions[-1]['trax_No']
        dout['trax_No'] = None
        dout['hash'] = 'Unverified'
        actual_balance_out = 0
        balanceNo_checker = self.Blocks('balance_No')
        
        # Collecting several inputs to formalize a transaction output.
        print("\n\033[1m\n======================= Zimcoin Transactians =======================\033[0m")
        sender_name = input("Enter your name: ")
        
        # Balance account verification for the recipient. Ivalid public keys are dismissed.
        recipient_public_key = input(f"\nHi {sender_name.upper()}! \nPlease, enter PUBLIC KEY of the recipient:\n")
        if recipient_public_key in balanceNo_checker:
            print("\033[1mThe balance number of the recipient has been verified!\033[0m")
                
        else:
            try_again = input(f"{sender_name.upper()}, you have not generated any transaction output! \nThe PUBLIC KEY you have typed is invalid. \nWould you like to try again? ")
            if try_again in self.yes_list:
                recipient_public_key = input("Please enter PUBLIC KEY of the recipient: ")
                if recipient_public_key in balanceNo_checker:
                    print("\033[1mThe balance number of the recipient has been verified!\033[0m")
                    
                else:
                    print("\n\033[1m=====================================================================\033[0m",
                          "\nSorry, the PUBLIC KEY you have tried is invalid. Have a nice day!!!")
                    return False, "transactian attempt!"
            else:
                print(f"\nOK, Have a nice day!!!")
                return False, "transactian attempt!"
        print("\n\033[1m=====================================================================\033[0m")
        
        # Verifying loop for the amount to send, no integers values are dismissed.
        while True:
            amount = input("Enter amonut to send: ")
            try:
                value = int(amount)
                if value > 1:
                    break
                else:
                    print("\n\033[1m '{input}'\033[0m is not valid amount! \nPlease try a positive integer number. ".format(input=amount))
            except ValueError:
                print("\n\033[1m '{input}'\033[0m is not valid amount! \nPlease try a positive integer number. ".format(input=amount))
        
        # Balance account verification for the sender. Invalid public keys are dismissed.
        public_key_output = input("\nPlease enter your PUBLIC KEY or balance number:\n")
        if public_key_output in balanceNo_checker:
            print("\033[1mYour balance number has been verified!\033[0m")
            for block in transactions:
                if public_key_output == block['balance_No'] and block['state'] == 'Verified' and block['zimcoins'] >= int(amount)+int(int(amount)*0.01):
                    dout['previous_hash'] = block['hash']
                    actual_balance_out = block['zimcoins']
                else:
                    continue
        else:
            print("\n\033[1m=====================================================================\033[0m")
            try_again = input(f"{sender_name.upper()}, you have not generated any transaction output! \nThe PUBLIC KEY you have typed is invalid. \nWould you like to try again? ")
            if try_again in self.yes_list:
                public_key_output = input("Please enter your PUBLIC KEY:\n")
                if public_key_output in balanceNo_checker:
                    print("\033[1mYour balance number has been verified!\033[0m")
                    for block in transactions:
                        if public_key_output == block['balance_No'] and block['state'] == 'Verified' and block['zimcoins'] >= int(amount)+int(int(amount)*0.01):
                            dout['previous_hash'] = block['hash']
                            actual_balance_out = block['zimcoins']
                        else:
                            continue
                else:
                    print("\n\033[1m=====================================================================\033[0m",
                          "\nSorry, the PUBLIC KEY you have tried is invalid. Have a nice day!!!")
                    return False, "transactian attempt!"
            else:
                print("\n\033[1m=====================================================================\033[0m",
                      "\nSorry, you have not generated any transaction output! Have a nice day!!!")
                return False, "transactian attempt!"
            
        # Data collection and printing out transaction details.
        dout['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f")
        dout['balance_No'] = public_key_output
        dout['zimcoins'] = int(amount)
        dout['fee'] = int(int(amount)*0.01)
        nonce = int.from_bytes(os.urandom(8), byteorder='little')
        dout['nonce'] = nonce
        dout['state'] = 'Unverified'
        print("\n\033[1mTransactian Details:\n====================\033[0m" + f"\n{sender_name.upper()}, you are sending",
              f"\033[1m{amount} Zimcoins \033[0mto:", f"\n\n\033[1mPUBLIC KEY:\033[0m \n{recipient_public_key}",
              f"\n\nTransaction Fee: {str(int(int(amount)*0.01))} Zimcoins.")
        
        # Data hashing and data signing of the transaction output.
        print("\033[1m=====================================================================\033[0m")
        private_key_output = input("\nTo \033[1mSIGN OUT\033[0m the transaction output please enter you PRIVATE KEY:\n")
        
        data_out = self.SHA1_hashing(bytes.fromhex(private_key_output), 
                                     bytes.fromhex(public_key_output),  
                                     str(nonce).encode('utf-8'), 
                                     str(dout['timestamp']).encode('utf-8'))
        
        h_out = self.SHA256_hashing(data_out, str(nonce).encode('utf-8'), bytes.fromhex(public_key_output)).hex()
        dout['hash'] = h_out 
        data_sign_out = self.SHA256_hashing(bytes.fromhex(recipient_public_key), bytes.fromhex(public_key_output), 
                                            str(amount).encode('utf-8'))
        
        # Verification of signature and private key. Invalid private keys are dismissed.
        try:
            signed_out = self.Sign_transaction(
            load_der_private_key(bytes.fromhex(private_key_output), password=b'testpassword'), data_sign_out)
            load_der_public_key(bytes.fromhex(public_key_output)).verify(signed_out, data_sign_out, ec.ECDSA(hashes.SHA256()))
            print("\033[1mValid private key!\033[0m")
        except InvalidSignature:
            print("\033[1m=====================================================================\033[0m",
                  "\n\033[1mThe output has not been signed. Invalid PRIVATE KEY!\033[0m")
            return False, "transactian attempt!"
        
        # Printing out previous and actual balance for the sender. 
        print("\033[1m=====================================================================\033[0m",
               f"\n\nOK {sender_name.upper()}, your transaction is in progress...\nPrevious balaces: ", f"{actual_balance_out} Zimcoins.",
               f"\nActual balance:\033[1m {int(actual_balance_out) - (int(amount)+int(int(amount)*0.01))} Zimcoins\033[0m.",
               "\n\033[1m=====================================================================\033[0m",
              "\nThe output is UNVERIFIED until a full confirmation of the blockchain.",)
        
        # Storing the transaction on the blockchain.
        trax_No = trax_No+1
        dout['trax_No'] = trax_No
        dout['signature'] = signed_out.hex()
        dout['status'] = 'Sent'
        transactions.append(dout)
        self.Update(transactions)