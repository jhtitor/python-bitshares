import unittest
from pprint import pprint
from bitshares import BitShares
from bitshares.instance import set_shared_blockchain_instance
from bitshares.fee import LocalFee
from bitshares.asset import Asset
from bitshares.amount import Amount
from bitsharesbase.operations import (
    Transfer,
    Blind_transfer,
    Transfer_to_blind,
    Transfer_from_blind
)
from bitsharesbase.objects import (
    Blind_input, Blind_output,
    Operation
)
from bitsharesbase.memo import encode_memo

wif = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
fee_asset = "BTS"

def mock_permission(pubkey):
    return {
        "weight_threshold": 1 if pubkey else 0,
        "account_auths": [ ],
        "key_auths": [ [str(pubkey), 1] ] if pubkey else [ ],
    }

def mock_memo(msg):
    from bitsharesbase.account import PublicKey, PrivateKey
    nonce = '16332877645293003478'
    pub = PrivateKey(wif).pubkey
    enc = encode_memo(PrivateKey(wif), pub, nonce, msg)
    return {
        "message": enc,
        "from": pub,
        "to": pub,
        "nonce": nonce
    }




class Testcases(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.bts = BitShares(
            nobroadcast=True,
            # We want to bundle many operations into a single transaction
            bundle=True,
            # Overwrite wallet to use this list of wifs only
            wif=[wif]
        )
        set_shared_blockchain_instance(self.bts)
        self.bts.set_default_account("init0")

    def test_fee_on_transfer(self):
        tx = self.bts.transfer("init1", 1, "1.3.0", account="init0", fee_asset="1.3.121")
        op = tx["operations"][0][1]
        self.assertEqual(op["fee"]["asset_id"], "1.3.121")

    def test_local_fee_transfer(self):
        fee_id = Asset("BTS", blockchain_instance=self.bts)["id"]
        memo = mock_memo("m" * 1024) # long message
        op = Transfer({ "from": "1.2.0", "to": "1.2.0",
            "amount": { "amount": 25000, "asset_id": "1.3.0" },
            "fee": { "amount": 20, "asset_id": fee_id },
            "memo": memo})

        local = LocalFee(op).amount()
        remote = Amount(
            self.bts.rpc.get_required_fees([Operation(op).json()], fee_id)[0],
            blockchain_instance=self.bts)
        self.assertEqual(local, remote)

    def test_local_fee_blind_transfer(self):
        fee_id = Asset("BTS", blockchain_instance=self.bts)["id"]
        op = Blind_transfer({
            "inputs": [ Blind_input(**{
                 "commitment": "1234",
                 "owner": mock_permission(None)})
            ],
            "outputs": [ Blind_output(**{
                 "commitment": "1234",
                 "range_proof": "",
                 "owner": mock_permission(None)})
            ],
            "fee": { "amount": 20, "asset_id": fee_id }})

        local = LocalFee(op).amount()
        remote = Amount(
            self.bts.rpc.get_required_fees([Operation(op).json()], fee_id)[0],
            blockchain_instance=self.bts)
        self.assertEqual(local, remote)

    def test_local_fee_transfer_to_blind(self):
        fee_id = Asset("BTS", blockchain_instance=self.bts)["id"]
        op = Transfer_to_blind({
            "from": "1.2.0",
            "outputs": [ Blind_output(**{
                 "commitment": "1234",
                 "range_proof": "",
                 "owner": mock_permission(None)})
            ],
            "blinding_factor": "1234",
            "amount": { "amount": 20, "asset_id": "1.3.0" },
            "fee": { "amount": 20, "asset_id": fee_id }})

        print(Operation(op).json()[0])
        local = LocalFee(op).amount()
        remote = Amount(
            self.bts.rpc.get_required_fees([Operation(op).json()], fee_id)[0],
            blockchain_instance=self.bts)
        self.assertEqual(local, remote)

    def test_local_fee_transfer_from_blind(self):
        fee_id = Asset("BTS", blockchain_instance=self.bts)["id"]
        op = Transfer_from_blind({
            "to": "1.2.0",
            "inputs": [ Blind_input(**{
                 "commitment": "1234",
                 "owner": mock_permission(None)})
            ],
            "blinding_factor": "1234",
            "amount": { "amount": 20, "asset_id": "1.3.0" },
            "fee": { "amount": 20, "asset_id": fee_id }})

        local = LocalFee(op).amount()
        remote = Amount(
            self.bts.rpc.get_required_fees([Operation(op).json()], fee_id)[0],
            blockchain_instance=self.bts)
        self.assertEqual(local, remote)
