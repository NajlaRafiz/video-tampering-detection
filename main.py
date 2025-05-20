from web3 import Web3
import json

# Connect to Ganache
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
print("Connected:", w3.is_connected())

# Set your default Ganache account
w3.eth.default_account = w3.eth.accounts[0]

# Load ABI from file
with open("contract_abi.json") as f:
    abi = json.load(f)

# Use your new Remix-deployed contract address
contract_address = "0xfD6d85708cdE6Fecf678cB10f1CE27FF9579a30b"
contract = w3.eth.contract(address=contract_address, abi=abi)

# Test storing and retrieving a hash
tx = contract.functions.storeHash("abc123", "Walk_Original").transact()
w3.eth.wait_for_transaction_receipt(tx)

# Retrieve and print stored hash
stored = contract.functions.getHash("Walk_Original").call()
print("Stored Hash from Blockchain:", stored)
