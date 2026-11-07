import os
from web3 import Web3
from solcx import compile_source, install_solc, set_solc_version

print("Installing Solidity compiler...")
install_solc('0.8.0')

print("Setting Solidity version...")
set_solc_version('0.8.0')

print("Reading smart contract...")
with open("contract.sol", "r") as file:
    contract_source = file.read()

print("Compiling contract...")
compiled = compile_source(contract_source)

contract_id, contract_interface = compiled.popitem()

abi = contract_interface['abi']
bytecode = contract_interface['bin']

print("Connecting to Ganache...")
ganache_url = os.environ.get("GANACHE_URL", "http://127.0.0.1:7545")
web3 = Web3(Web3.HTTPProvider(ganache_url))

print("Connected:", web3.is_connected())

account = web3.eth.accounts[0]

print("Deploying from account:", account)

LogStorage = web3.eth.contract(abi=abi, bytecode=bytecode)

tx_hash = LogStorage.constructor().transact({'from': account})

print("Transaction sent...")

tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

print("Contract deployed successfully!")
print("Contract Address:", tx_receipt.contractAddress)

contract_file = "/data/contract_address.txt" if os.path.isdir("/data") else "contract_address.txt"
try:
    with open(contract_file, "w") as f:
        f.write(tx_receipt.contractAddress)
    print(f"Contract address saved to {contract_file}")
except Exception as e:
    print(f"Failed to save contract address: {e}")