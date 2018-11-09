import logging
log = logging.getLogger(__name__)

try:
    from Crypto.Cipher import AES
except ImportError:
    raise ImportError("Missing dependency: pycrypto")

try:
    import secp256k1prp as secp256k1
    from secp256k1prp import Pedersen, ALL_FLAGS
except:
    raise ImportError("Missing dependency: secp256k1prp")

import struct
import hashlib
from binascii import hexlify, unhexlify

# AES
def _pad(s, BS):
    numBytes = (BS - len(s) % BS)
    return s + numBytes * struct.pack('B', numBytes)

def _unpad(s, BS):
    count = int(s[-1]) #int(struct.unpack('B', bytes(ls[0])))
    if s[-count::] == count * struct.pack('B', count):
        return s[:-count]
    return s

def aes_encrypt(sha512hex, raw):
    key = unhexlify(sha512hex[0:64])
    iv = unhexlify(sha512hex[64:96])
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt( _pad(raw, BS=16) )

def aes_decrypt(sha512hex, cipher):
    key = unhexlify(sha512hex[0:64])
    iv = unhexlify(sha512hex[64:96])
    aes = AES.new(key, AES.MODE_CBC, iv)
    return _unpad( aes.decrypt(cipher), BS=16)

# Pedersen / Rangeproof
from secp256k1prp import Pedersen, ALL_FLAGS

def perform_blinding(blind_factor, value):
    secp256k1 = Pedersen(None, ALL_FLAGS)
    result = secp256k1.pedersen_commit(blind_factor, value)
    return result

def blind_sum(factors, num_positive):
    secp256k1 = Pedersen(None, ALL_FLAGS)
    result = secp256k1.pedersen_blind_sum(factors, num_positive)
    return result

def verify_sum(pos_commits, neg_commits, excess):
    secp256k1 = Pedersen(None, ALL_FLAGS)
    result = secp256k1.pedersen_verify_tally(pos_commits, neg_commits, excess)
    return result

def range_proof_sign(min_value, commit, commit_blind, nonce, base10exp, min_bits, actual_value):
    secp256k1 = Pedersen(None, ALL_FLAGS)
    result = secp256k1.rangeproof_sign(min_value, commit, commit_blind, nonce, base10exp, min_bits, actual_value)
    return result

###############################################################
# UNUSED, BUT POTENTIALLY USABLE RANGEPROOF FUNCTIONS:
def range_proof_info(proof): # returns exponent, mantissa, min/max values
    secp256k1 = Pedersen(None, ALL_FLAGS)
    result = secp256k1.rangeproof_info(proof)
    return result
def range_proof_verify(commit, proof): # returns 1/0
    secp256k1 = Pedersen(None, ALL_FLAGS)
    result = secp256k1.rangeproof_verify(commit, proof)
    return result
# THIS ONE HAS THE MOST POTENTIAL, IT CAN RETURN RAW ASSET VALUES,
# GIVEN COMMITMENT, RANGEPROOF AND NONCE:
def range_proof_rewind(commit, proof, nonce): # returns a tuple
    secp256k1 = Pedersen(None, ALL_FLAGS)
    result = secp256k1.rangeproof_rewind(commit, proof, nonce)
    return result
#TODO: remove those functions? they aren't used, at all.
################################################################


# Utils
def _hex(s):
    return hexlify(s).decode('ascii')

def sha256hash(s):
    return hashlib.sha256(s).digest()

def sha256hex(s):
    return hashlib.sha256(s).hexdigest()

def sha512hash(s):
    return hashlib.sha512(s).digest()

def sha512hex(s):
    return hashlib.sha512(s).hexdigest()

from bitsharesbase.objects import Permission
def key_permission(pubkey):
    return Permission({
        "weight_threshold": 1 if pubkey else 0,
        "account_auths": [ ],
        "key_auths": [ [str(pubkey), 1] ] if pubkey else [ ],
    })

def _fourbytes(b):
    b = b[6:8] + b[4:6] + b[2:4] + b[0:2]
    return int(b, 16)

####
#### Private/Public Key helpers
####
#### TODO: Move to appropriate classes
from bitsharesbase.account import PrivateKey, PublicKey

def get_public_key(key):
#    from bitsharesbase.account import PublicKey
    if not(isinstance(key, PublicKey)):
        return PublicKey(key)
    return key

def get_shared_secret512(priv, pub):
    #from secp256k1 import PublicKey as SECPPublicKey
    #pre = SECPPublicKey(bytes(pub), True)
    #key = pre.tweak_mul(bytes(priv))
    #return sha512hash(key.serialize()[1:])
    from bitsharesbase.memo import get_shared_secret
    secretHH = get_shared_secret(priv, pub)
    return sha512hash(unhexlify(secretHH))

def public_key_child(pk, child256):
    s = bytes(pk)
    s += child256
    h = sha256hash(s)
    pk.add(h)

def private_key_child(priv, offset256):
    s = bytes( priv.pubkey ) + offset256
    h = sha256hash(s)
    secret = priv.get_secret()
    secret = generate_from_seed( bytes(priv), h )
    return secret

import ecdsa
def generate_from_seed(seed, offset):
     seed = int(_hex(seed), 16)
     z = int(_hex(offset), 16)
     order = ecdsa.SECP256k1.order

     secexp = (seed + z) % order

     secret = "%0x" % secexp
     return PrivateKey(secret)

###
### Blind transfers
###

from graphenebase.base58 import b58encode, b58decode

from bitshares.transactionbuilder import TransactionBuilder
from bitsharesbase.operations import Transfer_to_blind
from bitsharesbase.operations import Transfer_from_blind
from bitsharesbase.operations import Blind_transfer
from bitsharesbase.objects import Blind_input
from bitsharesbase.objects import Blind_output
from bitsharesbase.objects import Stealth_Confirmation
from bitsharesbase.objects import Stealth_Confirmation_MemoData
from bitshares.amount import Amount

def create_blind_account(brain_key_str):
    from bitsharesbase.account import BrainKey
    bk = BrainKey(brain_key_str)
    return bk.get_blind_private()

from bitshares.fee import LocalFee
def calculate_fee(bitshares_instance, op, asset_obj=None, opclass=None):
    if asset_obj:
        op["fee"] = { "amount": 0, "asset_id": asset_obj["id"] }
    return LocalFee(op, opclass=opclass, blockchain_instance=bitshares_instance).json()

def transfer_to_blind(bitshares_instance, from_account_id_or_name, base_outputs, symbol, broadcast=False, fee_asset_id="1.3.0", debug_priv=None):
    bts = bitshares_instance
    wallet = bts.wallet
    ws = wallet.rpc
    from_account = ws.get_account(from_account_id_or_name)
    asset_obj = ws.get_asset(symbol)

    confirm, balances = gen_blind_outputs(base_outputs, asset_obj["id"], debug_priv)

    for balance in balances:
        balance["description"] = "from @" + from_account["name"]

    confirm["balances"] = balances

    to_blind = { }
    to_blind["from"] = from_account["id"]
    to_blind["outputs"] = confirm["outputs"]
    to_blind["amount"] = confirm["amount"]
    to_blind["blinding_factor"] = confirm["blinding_factor"]
    to_blind["fee"] = { "amount": 0, "asset_id": fee_asset_id }

    confirm["trx"] = TransactionBuilder(bitshares_instance = bitshares_instance)
    confirm["trx"].appendOps( Transfer_to_blind(**to_blind) )
    confirm["trx"].appendSigner(from_account["id"], "active")

    if broadcast:
        confirm["trx"] = confirm["trx"].sign()
        confirm["trx"].broadcast()

        try_to_receive_blind_transfers(wallet, balances, "@"+from_account["name"])

    return confirm

def try_to_receive_blind_transfers(wallet, balances, opt_from, throw=False):
    for balance in balances:
        try:
            receive_blind_transfer(wallet, balance["receipt"], opt_from, balance["description"] )
        except:
            if throw:
                raise

def gen_blind_outputs(base_outputs, asset_id, debug_priv=None):
    """
        :param base_outputs List of [PUBKEY, amount] tuples
        :param str Asset ID
    """
    blinding_factors = [ ]
    outputs = [ ]
    out_balances = [ ]

    total_amount = 0

    for to_key_or_label, amount in base_outputs:

        one_time_key = PrivateKey(debug_priv) # generate new random key
        to_key = get_public_key(to_key_or_label)

        secret512 = get_shared_secret512( one_time_key, to_key )

        child = sha256hash( secret512 )
        nonce = one_time_key.get_secret()
        blind_factor = sha256hash( child )

        blinding_factors.append( bytes(blind_factor) )

        total_amount += amount

        out = { }
        out["owner"] = key_permission( to_key.child(child) )
        out["commitment"] = perform_blinding( blind_factor, amount )
        out["range_proof"] = ""

        if len(base_outputs) > 1:
            out["range_proof"] = range_proof_sign( 0, out["commitment"], blind_factor, nonce, 0, 0, amount )
            out["range_proof"] = _hex( out["range_proof"] )

        balance = gen_receipt(
            None, to_key, one_time_key,
            blind_factor, out["commitment"], secret512,
            amount, asset_id, out["owner"])

        out["commitment"] = _hex(out["commitment"])

        outputs.append(out)

        out_balances.append(balance)

    # sort outputs by commitment
    outputs = sorted(outputs, key=lambda o: o["commitment"])

    return {
        "amount": { "amount": total_amount, "asset_id": asset_id },
        "blinding_factor": _hex( blind_sum(blinding_factors, len(blinding_factors)) ),
        "outputs": outputs,
    }, out_balances


def gen_receipt(from_key, to_key, one_time_key,
                blind_factor, commitment, secret512,
                amount_int, asset_id,
                control_authority):

    secretHEX = _hex(secret512)

    memo = Stealth_Confirmation_MemoData(**{
        "from": str(from_key) if from_key else None,
        "amount": {"amount": amount_int, "asset_id": asset_id},
        "blinding_factor": blind_factor,
        "commitment": commitment,
        "check": _fourbytes(secretHEX)
    })

    conf = Stealth_Confirmation(**{
        "one_time_key": str(one_time_key.pubkey),
        "to": str(to_key),
        "encrypted_memo": _hex( aes_encrypt(secretHEX, bytes(memo)) ),
    })

    receipt = b58encode( _hex( bytes(conf) ) ) # Most important piece of data

    log.info(" Blind Receipt: %s" % (str(receipt)))

    balance = {
        "control_authority": control_authority,
        "memodata"         : memo,
        "confirmation"     : conf,
        "commitment"     : str(memo.data["commitment"]),
        "receipt"        : str(receipt),
        "amount"         : int(amount_int),
        "asset_id"       : str(asset_id),
        "to"             : str(to_key),
        "from"           : str(from_key) if from_key else None,
        "one_time_key"   : str(conf.data["one_time_key"]),
        "blinding_factor": str(memo.data["blinding_factor"]),
        "used"           : False,
        "description": "",
    }

    return balance

def open_receipt(wallet, confirmation_receipt, description=""):

    receipt = unhexlify( b58decode(confirmation_receipt) )

    conf = Stealth_Confirmation.fromBytes(receipt)[0].data

    to_priv_key = wallet.getPrivateKeyForPublicKey(str(conf["to"].data))
    if not to_priv_key:
        from .exceptions import MissingKeyError
        raise MissingKeyError
    if not(isinstance(to_priv_key, PrivateKey)):
        to_priv_key = PrivateKey(to_priv_key)

    secret512 = get_shared_secret512(to_priv_key, conf["one_time_key"])

    cipher = conf["encrypted_memo"].data

    plain_memo = aes_decrypt( _hex(secret512), cipher )

    try:
        memo = Stealth_Confirmation_MemoData.fromBytes(plain_memo)[0].data
    except:
        raise ValueError("Unable to read decrypted data")

    #confirm the amount matches the commitment (verify the blinding factor)
    commitment_test = perform_blinding( memo["blinding_factor"], int( memo["amount"].data["amount"].data ) )
    assert verify_sum( [commitment_test], [ bytes(memo["commitment"])], 0 )

    child = sha256hash( secret512 )

    child_priv_key = to_priv_key.child(child) #private_key_child(to_priv_key, child)
    child_pub_key = child_priv_key.pubkey

    balance = {
        "control_authority": key_permission(child_pub_key),
        "memodata"         : memo,
        "confirmation"     : conf,
        "commitment"     : str(memo["commitment"]),
        "receipt"        : str(confirmation_receipt),
        "amount"         : int(memo["amount"].data["amount"].data),
        "asset_id"       : str(memo["amount"].data["asset_id"]),
        "to"             : str(conf["to"].data),
        "from"           : str(memo["from"].data) if memo["from"].data else None,
        "one_time_key"   : str(conf["one_time_key"]),
        "blinding_factor": str(memo["blinding_factor"]),
        "used"           : False,
        "description": description,
    }

    return balance, child_priv_key


def receive_blind_transfer(wallet, confirmation_receipt, opt_from="", opt_memo=""):
    log.info("Attempting to receive blind transfer %s" % (confirmation_receipt))

    balance, child_priv_key = open_receipt(wallet, confirmation_receipt, opt_memo)

    child_wif = str(child_priv_key)

    ok = 0
    try:
        wallet.storeBlindBalance(balance)
        ok += 1
    except Exception as e:
        #print(e)
        pass
    try:
        wallet.addPrivateKey(child_wif)
        ok += 1
    except Exception as e:
        #print(e)
        pass

    return bool(ok), balance, child_wif


def transfer_from_blind(bitshares_instance,
                        from_blind_account_key_or_label,
                        to_account_id_or_name,
                        amount,
                        symbol,
                        broadcast, debug_priv=None):

    bts = bitshares_instance
    wallet = bts.wallet
    ws = wallet.rpc

    to_account = ws.get_account(to_account_id_or_name)
    asset_obj = ws.get_asset(symbol)

    if not(isinstance(amount, int)): # O_O
        amount = int(Amount(amount, symbol, bitshares_instance=bitshares_instance))

    in_amount = { "amount": amount, "asset_id": asset_obj["id"] }

    from_blind = { }
    #d = Transfer_from_blind(**from_blind)
    #from_blind["fee"] = ws.get_required_fees([[41,d.json()]], asset_obj["id"])[0]
    from_blind["fee"] = calculate_fee(bts, from_blind, asset_obj, opclass=Transfer_from_blind)

    blind_in = { "amount": from_blind["fee"]["amount"] + in_amount["amount"], "asset_id": asset_obj["id"] }

    #print("CREATED `blind_in`:", blind_in, "FEE:", from_blind["fee"], "amount:", amount)

    confirm = blind_transfer_help(bitshares_instance,
                                from_blind_account_key_or_label,
                                from_blind_account_key_or_label,
                                blind_in["amount"], asset_obj,
                                broadcast=False, to_temp=True, sign=False, # !
                                debug_priv=debug_priv)

    assert len(confirm["balances"]) > 0
    balance = confirm["balances"][-1]

    balance["description"] = "to @" + to_account["name"]

    from_blind["to"] = to_account["id"]
    from_blind["amount"] = in_amount
    from_blind["blinding_factor"] = balance["blinding_factor"]# output["decrypted_memo"].json()["blinding_factor"]
    from_blind["inputs"] = [ Blind_input(**{
        "owner": key_permission(None),
        "commitment": balance["commitment"], #output["decrypted_memo"].json()["commitment"],
    }) ]

    #from_blind["fee"] = fees.calculate_fee( from_blind, asset_obj.options.core_exchange_rate )
    #d = Transfer_from_blind(**from_blind)
    #from_blind["fee"] = ws.get_required_fees([[d.json()]], asset_obj["id"])[0]

    confirm["trx"].appendOps( Transfer_from_blind(**from_blind) )
    #confirm["trx"].appendSigner(to_account["id"], "active")

    if broadcast:
        confirm["trx"] = confirm["trx"].sign()
        confirm["trx"].broadcast()

    if (broadcast and len(confirm["balances"]) == 2):
        change_balance = confirm["balances"][0]
        try:
            receive_blind_transfer(wallet, change_balance["receipt"], from_blind_account_key_or_label, "change @" + to_account["name"])
        except:
            pass

    return confirm

class BlindBalanceMismatch(Exception):
    """ Sweeping a blind balance requires a single output
        and a reduced fee. If you see this error, try
        increasing(!) or decreasing the output amount.
    """
    pass

def match_blind_input_outputs(bitshares_instance, amount_in, asset_obj, inputs, num_outputs = 2):
    assert num_outputs == 1 or num_outputs == 2
    bts = bitshares_instance
    wallet = bts.wallet
    #ws = wallet.rpc

    in_amount = { "amount": amount_in, "asset_id": asset_obj["id"] }
    total_amount = { "amount": 0, "asset_id": asset_obj["id"] }
    #blinding_factors = [ ]

    blconfirm = {
        "inputs": [ ],
        "balances": [ ],
    }

    blind_tr = { }
    blind_tr["inputs"] = [ ]
    blind_tr["outputs"] = [ None ] * num_outputs
    blind_tr["fee"] = { "amount": 0, "asset_id": asset_obj["id"] }

    blind_tr["fee"] = calculate_fee(bts, blind_tr, asset_obj, opclass=Blind_transfer)

    def test_eq(a, b):
        return a == b
    def test_ge(a, b):
        return a >= b
    test = [test_eq, test_ge][num_outputs-1]

    for balance in inputs:

        blind_tr["inputs"].append(Blind_input(**{
          "owner": balance["control_authority"],
          "commitment": balance["commitment"],
        }))

        blconfirm["inputs"].append(balance) # Keep track of receipts for user

        #blinding_factors.append( unhexlify(balance["blinding_factor"]) )
        total_amount["amount"] += balance["amount"]

        if test(total_amount["amount"], in_amount["amount"] + blind_tr["fee"]["amount"]):
            break
        #if total_amount["amount"] >= in_amount["amount"] + blind_tr["fee"]["amount"]:
        #   break

    change = total_amount["amount"] - in_amount["amount"] - blind_tr["fee"]["amount"]

    from .exceptions import InsufficientBlindBalance
    if not((total_amount["amount"] >= in_amount["amount"] + blind_tr["fee"]["amount"])):
        raise InsufficientBlindBalance("%d < %d + %d fee" % (
         total_amount["amount"],
         in_amount["amount"], blind_tr["fee"]["amount"]
        ), input_adjust=change, asset_obj=asset_obj )

    if change == 0 and num_outputs == 2:
        raise BlindBalanceMismatch("Can't have zero change with 2 outputs")
    if change > 0 and num_outputs == 1:
        raise BlindBalanceMismatch("Can't have non-zero change with 1 output")

    return blconfirm, change, blind_tr

def refresh_blind_balances(wallet, balances, storeback=True):
    """ Given a list of (supposedly) unspent balances, iterate over each one
        and verify it's status on the blockchain. Each balance failing
        this verification updates own status in the database (if storeback is True).
        Returns a list of TRULY unspent balances.
    """
    rpc = wallet.rpc
    unspent = [ ]

    for balance in balances:
        result = rpc.get_blinded_balances([balance["commitment"]])
        if len(result) == 0:
            if storeback:
                wallet.modifyBlindBalance(balance["commitment"], used=True)
        else:
            unspent.append(balance)

    return unspent


def blind_transfer_help( bitshares_instance,
                         from_key_or_label,
                         to_key_or_label,
                         amount_in,
                         asset_obj,
                         broadcast,
                         to_temp, sign, debug_priv=None ):
    blconfirm = {
        "inputs": [ ],
        "balances": [ ],
    }

    bts = bitshares_instance
    wallet = bts.wallet
    ws = wallet.rpc

    from_key = get_public_key(from_key_or_label)
    to_key   = get_public_key(to_key_or_label)

    #asset_obj = ws.get_asset(symbol)

    balances = wallet.getBlindBalances(pub_to=str(from_key), asset_id=asset_obj["id"], used=False)

    balances = refresh_blind_balances(wallet, balances, storeback=True)

    # It might be possible to squeeze a blind transaction into a single output, reducing the fee.
    # Therefore, we try BOTH paths and see if we can get away with it.
    # NOTE: this is still suboptimal:
    #  a) this will still fail to sweep a blind balance (if the users assumes 2x fee)
    #  b) match_blind_input_outputs DOES NOT perform any fancy algorithms to find best possible
    #     inputs for the required output
    errorA = None
    errorB = None
    try:
        blconfirmA, changeA, blind_trA = match_blind_input_outputs(bts, amount_in, asset_obj, balances, 2)
    except Exception as error:
        #log.error(str(error))
        errorA = error
    try:
        blconfirmB, changeB, blind_trB = match_blind_input_outputs(bts, amount_in, asset_obj, balances, 1)
    except Exception as error:
        #log.error(str(error))
        errorB = error
    # Given 2 paths (and possible errors on either/both), select one
    if errorA and errorB:
        if not(isinstance(errorB, BlindBalanceMismatch)):
            raise errorB # guide to cheaper solution
        raise errorA
    if not(errorB): # pick path B if possible
        blconfirm = blconfirmB
        change = changeB
        blind_tr = blind_trB
    elif not(errorA):
        blconfirm = blconfirmA
        change = changeA
        blind_tr = blind_trA
    else:
        raise Exception # ?

    # Go on
    in_amount = { "amount": amount_in, "asset_id": asset_obj["id"] }

    blinding_factors = [ ]
    for balance in blconfirm["inputs"]:
        blinding_factors.append( unhexlify(balance["blinding_factor"]) )

    #one_time_key = PrivateKey() # generate new random key
    one_time_key = PrivateKey(debug_priv)

    secret512    = get_shared_secret512( one_time_key, to_key )
    child        = sha256hash( secret512 )
    nonce        = one_time_key.get_secret()
    blind_factor = sha256hash( child )

    from_secret512= get_shared_secret512( one_time_key, from_key )
    from_child    = sha256hash( from_secret512 )
    from_nonce    = sha256hash( nonce )

    #change = total_amount["amount"] - in_amount["amount"] - blind_tr["fee"]["amount"]

    if change > 0:
        blinding_factors.append( bytes(blind_factor) )
        change_blind_factor = blind_sum( blinding_factors, len(blinding_factors) - 1)
    else: # change == 0
        blind_factor = blind_sum( blinding_factors, len(blinding_factors) )
        blinding_factors.append( bytes(blind_factor) )

    to_out = {
        "owner": key_permission(None) if to_temp else key_permission( to_key.child( child ) ),
        "commitment": perform_blinding( blind_factor, in_amount["amount"] ),
        "range_proof": ""
    }

    if change > 0:
        to_out["range_proof"] = range_proof_sign( 0, to_out["commitment"], blind_factor, nonce,  0, 0, in_amount["amount"] )
        to_out["range_proof"] = _hex(to_out["range_proof"])

        change_out = {
            "owner": key_permission( from_key.child( from_child ) ),
            "commitment": perform_blinding( change_blind_factor, change ),
        }
        change_out["range_proof"] = range_proof_sign( 0, change_out["commitment"], change_blind_factor, from_nonce, 0, 0, change )
        change_out["range_proof"] = _hex(change_out["range_proof"])

        balance = gen_receipt(
            from_key, from_key, one_time_key,
            change_blind_factor, change_out["commitment"], from_secret512,
            change, asset_obj["id"], change_out["owner"])

        change_out["commitment"] = _hex(change_out["commitment"])

        blconfirm["balances"].append(balance)

        blind_tr["outputs"] = [ to_out, change_out ]
    else:
        blind_tr["outputs"] = [ to_out ]

    balance = gen_receipt(
        from_key, to_key, one_time_key,
        blind_factor, to_out["commitment"], secret512,
        in_amount["amount"], asset_obj["id"], to_out["owner"])

    to_out["commitment"] = _hex(to_out["commitment"])

    if to_temp:
        balance["to"] = None

    blconfirm["balances"].append(balance)

    blconfirm["trx"] = TransactionBuilder(bitshares_instance = bitshares_instance)
    blconfirm["trx"].appendOps( Blind_transfer(**blind_tr) )
    for input_balance in blconfirm["inputs"]:
        ca = input_balance["control_authority"]
        if isinstance(ca, Permission):
            ca = ca.json()
        ts = float(ca["weight_threshold"])
        for key, weight in ca["key_auths"]:
            from_wif = wallet.getPrivateKeyForPublicKey(key)
            if from_wif:
                blconfirm["trx"].appendWif(from_wif)

                ts -= float(weight)
                if ts <= 0:
                    break

    if broadcast or sign:
        blconfirm["trx"] = blconfirm["trx"].sign()

    if broadcast:
        blconfirm["trx"].broadcast()

        try_to_receive_blind_transfers(wallet, blconfirm["balances"], from_key_or_label)

    return blconfirm

def blind_transfer(bitshares_instance,
                   from_key_or_label,
                   to_key_or_label,
                   amount,
                   symbol,
                   broadcast, sign=True, debug_priv=None):

    wallet = bitshares_instance.wallet
    ws = wallet.rpc
    asset_obj = ws.get_asset(symbol)
    #amount = { "amount": int(amount_str), "asset_id": asset_obj["id"] }
    if not(isinstance(amount, int)):
        amount = int(Amount(amount, symbol, bitshares_instance=bitshares_instance))

    return blind_transfer_help(bitshares_instance,
            from_key_or_label,
            to_key_or_label,
            amount, asset_obj,
            broadcast, to_temp=False, sign=sign, debug_priv=debug_priv)
