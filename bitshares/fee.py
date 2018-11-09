from .instance import BlockchainInstance
from .asset import Asset
from .amount import Amount
from bitsharesbase.operations import (
    Operation
)
from graphenebase.types import Array


class OperationsFee(list):
    """ Obtain the fee associated with an actual operation

        :param list operations: list of operations as dictionary
        :param bitshares.asset.Asset: Asset to pay fee in
        :param bitshares blockchain_instance: BitShares() instance to use when
            accesing a RPC
    """
    def __init__(self, opsOrg, asset="1.3.0", **kwargs):
        ops = opsOrg.copy()
        assert isinstance(ops, list)

        BlockchainInstance.__init__(self, **kwargs)
        asset = Asset(
            asset,
            blockchain_instance=self.blockchain)

        if isinstance(ops[0], (object, dict)):
            ops = [Operation(i) for i in ops]

        fees = self.blockchain.rpc.get_required_fees(
            [i.json() for i in ops], asset["id"])
        ret = []
        for i, d in enumerate(ops):
            if isinstance(fees[i], list):
                # Operation is a proposal
                ret.append([Amount(dict(
                    amount=fees[i][0]["amount"],
                    asset_id=fees[i][0]["asset_id"]),
                    blockchain_instance=self.blockchain
                )])
                for j, _ in enumerate(ops[i].op.data["proposed_ops"].data):
                    ret[-1].append(
                        Amount(dict(
                            amount=fees[i][1][j]["amount"],
                            asset_id=fees[i][1][j]["asset_id"]),
                            blockchain_instance=self.blockchain
                        ))
            else:
                # Operation is a regular operation
                ret.append(Amount(dict(
                    amount=fees[i]["amount"],
                    asset_id=fees[i]["asset_id"]),
                    blockchain_instance=self.blockchain
                ))
        list.__init__(self, ret)


class Fee(dict):
    """ Obtain fees associated with individual operations on the blockchain

        :param str identifier: Operation id or name
        :param bitshares blockchain_instance: BitShares() instance to use when
            accesing a RPC

    """
    pass

# TODO: This fee calculator is not entirely production-ready,
# in particular price_per_kbyte was never tested
# But! It should work just fine when blind transfers are concerned.
class LocalFee():
    """
        You can pass one of `bitsharesbase.operations` objects
        to the constructor.

        op = Transfer({ ... })
        fee = LocalFee(op)

        You may also use raw `dict`, in which case `opclass`
        argument MUST be provided.

        fee = LocalFee({ ... }, opclass=Transfer)

        To get the result, use `amount` or `json` methods:

        fee = LocalFee(op).amount() # return Amount object
        fee = LocalFee({ ... }, opclass=Transfer).json() # amount as dict
    """
    def __init__(self, op, opclass=None, **kwargs):
        BlockchainInstance.__init__(self, **kwargs)
        if "fee" in op:
            fee_asset = Asset(str(op["fee"]["asset_id"]), blockchain_instance=self.blockchain)
        else:
            fee_asset = Asset("1.3.0", blockchain_instance=self.blockchain)
        core_exchange_rate = fee_asset["options"]["core_exchange_rate"]
        self.raw = self.calculate_fee(op, core_exchange_rate, opclass)

    def amount(self):
        return Amount(dict(
                amount=self.raw["amount"],
                asset_id=self.raw["asset_id"]),
                blockchain_instance=self.blockchain)

    def json(self):
        return self.raw

    def _get_fee_parameters(self):
        rpc = self.blockchain.rpc
        _fees = rpc.get_global_properties()["parameters"]["current_fees"]["parameters"]
        fees = { }
        for fee_id, data in _fees:
            fees[int(fee_id)] = data
        GRAPHENE_BLOCKCHAIN_PRECISION = rpc.get_config()["GRAPHENE_BLOCKCHAIN_PRECISION"]
        #fees[39] = { # transfer_to_blind
        #    "fee": 5*GRAPHENE_BLOCKCHAIN_PRECISION,
        #    "price_per_output": 5*GRAPHENE_BLOCKCHAIN_PRECISION
        #}
        fees[40] = { # blind_transfer
            "fee": 5*GRAPHENE_BLOCKCHAIN_PRECISION,
            "price_per_output": 5*GRAPHENE_BLOCKCHAIN_PRECISION
        }
        #fees[41] = { # transfer_from_blind
        #    "fee": 5*GRAPHENE_BLOCKCHAIN_PRECISION,
        #}
        return fees

    def calculate_fee(self, op, core_exchange_rate, opclass=None):
        if not(hasattr(self.blockchain, 'fee_params')):
            self.blockchain.fee_params = self._get_fee_parameters()

        if opclass is None: opclass = op.__class__

        from bitsharesbase.operations import getOperationIdForClass
        op_id = int(getOperationIdForClass(opclass.__name__))
        if not op_id in self.blockchain.fee_params:
            raise KeyError("No fee data for operation " + str(op_id))

        k = self.blockchain.fee_params[op_id]

        base_value = int(k["fee"])
        if "price_per_output" in k:
            n = op["outputs"].length.data if isinstance(op["outputs"], Array) else len(op["outputs"])
            base_value += int(n) * int(k["price_per_output"])
        if "price_per_kbyte" in k:
            if hasattr(opclass, 'fee_bytes'):
                b = opclass.fee_bytes(op)
            else:
                b = len(bytes(op))
            base_value += int(b * int(k["price_per_kbyte"]) / 1024)

        final_id = core_exchange_rate["quote"]["asset_id"]
        scale = int(core_exchange_rate["quote"]["amount"]) / int(core_exchange_rate["base"]["amount"])
        rescale = int(core_exchange_rate["base"]["amount"]) / int(core_exchange_rate["quote"]["amount"])
        if final_id == "1.3.0":
            rescale, scale = scale, rescale
            final_id = core_exchange_rate["base"]["asset_id"]
        value = int(base_value * scale)
        scaled = int(base_value * scale * rescale)
        while value * rescale < scaled:
            value += 1

        return { "amount": value, "asset_id": final_id }
