import logging
import os
from graphenebase import bip38
from bitsharesbase.account import PrivateKey
from .storage import get_default_key_store, InRamPlainKeyStore
from .storage import get_default_blind_store
from .instance import BlockchainInstance
from .account import Account
from .exceptions import (
    KeyNotFound,
    InvalidWifError,
    WalletExists,
    WalletLocked,
    NoWalletException,
    OfflineHasNoRPCException,
    KeyAlreadyInStoreException
)


log = logging.getLogger(__name__)


class Wallet():
    """ The wallet is meant to maintain access to private keys for
        your accounts. It either uses manually provided private keys
        or uses a SQLite database managed by storage.py.

        :param BitSharesNodeRPC rpc: RPC connection to a BitShares node
        :param array,dict,string keys: Predefine the wif keys to shortcut the
               wallet database

        Three wallet operation modes are possible:

        * **Wallet Database**: Here, pybitshares loads the keys from the
          locally stored wallet SQLite database (see ``storage.py``).
          To use this mode, simply call ``BitShares()`` without the
          ``keys`` parameter
        * **Providing Keys**: Here, you can provide the keys for
          your accounts manually. All you need to do is add the wif
          keys for the accounts you want to use as a simple array
          using the ``keys`` parameter to ``BitShares()``.
        * **Force keys**: This more is for advanced users and
          requires that you know what you are doing. Here, the
          ``keys`` parameter is a dictionary that overwrite the
          ``active``, ``owner``, ``posting`` or ``memo`` keys for
          any account. This mode is only used for *foreign*
          signatures!
    """
    def __init__(self, *args, **kwargs):
        BlockchainInstance.__init__(self, *args, **kwargs)

        # Compatibility after name change from wif->keys
        if "wif" in kwargs and "keys" not in kwargs:
            kwargs["keys"] = kwargs["wif"]

        if "keys" in kwargs:
            self.key_store = InRamPlainKeyStore()
            self.setKeys(kwargs["keys"])
        else:
            if 'key_store' in kwargs:
                self.key_store = kwargs["key_store"]
            else:
                self.key_store = get_default_key_store(
                    config=self.blockchain.config
                )

        if "blind_store" in kwargs:
            self.blind_store = kwargs["blind_store"]
        else:
            self.blind_store = get_default_blind_store()


    @property
    def prefix(self):
        if self.blockchain.is_connected():
            prefix = self.blockchain.prefix
        else:
            # If not connected, load prefix from config
            prefix = self.blockchain.config["prefix"]
        return prefix or "BTS"   # default prefix is BTS

    @property
    def rpc(self):
        if not self.blockchain.is_connected():
            raise OfflineHasNoRPCException("No RPC available in offline mode!")
        return self.blockchain.rpc

    def setKeys(self, loadkeys):
        """ This method is strictly only for in memory keys that are
            passed to Wallet/BitShares with the ``keys`` argument
        """
        log.debug(
            "Force setting of private keys. Not using the wallet database!")
        if isinstance(loadkeys, dict):
            loadkeys = list(loadkeys.values())
        elif not isinstance(loadkeys, list):
            loadkeys = [loadkeys]
        for wif in loadkeys:
            pub = format(PrivateKey(str(wif)).pubkey, self.prefix)
            self.key_store.add(str(wif), pub)

    def is_encrypted(self):
        """ Is the key store encrypted?
        """
        return self.key_store.is_encrypted()

    def unlock(self, pwd):
        """ Unlock the wallet database
        """
        if self.key_store.is_encrypted():
            return self.key_store.unlock(pwd)

    def lock(self):
        """ Lock the wallet database
        """
        if self.key_store.is_encrypted():
            return self.key_store.lock()
        else:
            return False

    def unlocked(self):
        """ Is the wallet database unlocked?
        """
        if self.key_store.is_encrypted():
            return not self.key_store.locked()
        else:
            return True

    def locked(self):
        """ Is the wallet database locked?
        """
        if self.key_store.is_encrypted():
            return self.key_store.locked()

    def changePassphrase(self, new_pwd):
        """ Change the passphrase for the wallet database
        """
        self.masterpwd.changePassword(new_pwd)

    def created(self):
        """ Do we have a wallet database already?
        """
        if len(self.key_store.getPublicKeys()):
            # Already keys installed
            return True
        else:
            return False

    def create(self, pwd):
        """ Alias for newWallet()
        """
        pass

    def newWallet(self, pwd):
        """ Create a new wallet database
        """
        pass

    def addPrivateKey(self, wif):
        """ Add a private key to the wallet database
        """
        try:
            pub = format(PrivateKey(str(wif)).pubkey, self.prefix)
        except:
            raise InvalidWifError("Invalid Key format!")
        if str(pub) in self.key_store:
            raise KeyAlreadyInStoreException("Key already in the store")
        self.key_store.add(str(wif), str(pub))

    def getPrivateKeyForPublicKey(self, pub):
        """ Obtain the private key for a given public key

            :param str pub: Public Key
        """
        if str(pub) not in self.key_store:
            raise KeyNotFound
        return self.key_store.getPrivateKeyForPublicKey(str(pub))

    def removePrivateKeyFromPublicKey(self, pub):
        """ Remove a key from the wallet database
        """
        self.key_store.delete(str(pub))

    def removeAccount(self, account):
        """ Remove all keys associated with a given account
        """
        accounts = self.getAccounts()
        for a in accounts:
            if a["name"] == account:
                self.key_store.delete(a["pubkey"])

    def getOwnerKeyForAccount(self, name):
        """ Obtain owner Private Key for an account from the wallet database
        """
        account = self.rpc.get_account(name)
        for authority in account["owner"]["key_auths"]:
            key = self.getPrivateKeyForPublicKey(authority[0])
            if key:
                return key
        raise KeyNotFound

    def getMemoKeyForAccount(self, name):
        """ Obtain owner Memo Key for an account from the wallet database
        """
        account = self.rpc.get_account(name)
        key = self.getPrivateKeyForPublicKey(
            account["options"]["memo_key"])
        if key:
            return key
        return False

    def getActiveKeyForAccount(self, name):
        """ Obtain owner Active Key for an account from the wallet database
        """
        account = self.rpc.get_account(name)
        for authority in account["active"]["key_auths"]:
            key = self.getPrivateKeyForPublicKey(authority[0])
            if key:
                return key
        return False

    def getAccountFromPrivateKey(self, wif):
        """ Obtain account name from private key
        """
        pub = format(PrivateKey(wif).pubkey, self.prefix)
        return self.getAccountFromPublicKey(pub)

    def getAccountsFromPublicKey(self, pub):
        """ Obtain all accounts associated with a public key
        """
        names = self.rpc.get_key_references([str(pub)])
        for name in names:
            for i in name:
                yield i

    def getAccountFromPublicKey(self, pub):
        """ Obtain the first account name from public key
        """
        # FIXME, this only returns the first associated key.
        # If the key is used by multiple accounts, this
        # will surely lead to undesired behavior
        names = self.rpc.get_key_references([str(pub)])[0]
        if not names:
            return None
        else:
            return names[0]

    def getAllAccounts(self, pub):
        """ Get the account data for a public key (all accounts found for this
            public key)
        """
        for id in self.getAccountsFromPublicKey(str(pub)):
            try:
                account = Account(id, blockchain_instance=self.blockchain)
            except:
                continue
            yield {"name": account["name"],
                   "account": account,
                   "type": self.getKeyType(account, str(pub)),
                   "pubkey": str(pub)}

    def getKeyType(self, account, pub):
        """ Get key type
        """
        for authority in ["owner", "active"]:
            for key in account[authority]["key_auths"]:
                if str(pub) == key[0]:
                    return authority
        if str(pub) == account["options"]["memo_key"]:
            return "memo"
        return None

    def getAccounts(self):
        """ Return all accounts installed in the wallet database
        """
        pubkeys = self.getPublicKeys()
        accounts = []
        for pubkey in pubkeys:
            # Filter those keys not for our network
            if pubkey[:len(self.prefix)] == self.prefix:
                accounts.extend(self.getAllAccounts(pubkey))
        return accounts

    def getPublicKeys(self):
        """ Return all installed public keys
        """
        return self.key_store.getPublicKeys()

    def wipe(self, sure=False):
        if not sure:
            log.error(
                "You need to confirm that you are sure "
                "and understand the implications of "
                "wiping your wallet!"
            )
            return
        else:
            self.key_store.wipe()

    def storeBlindBalance(self, balance):
        balance["control_authority"] = balance["control_authority"].json()
        balance.pop("memodata")
        balance.pop("confirmation")
        return self.blind_store.add(balance["commitment"], balance)

    def getBlindBalance(self, commitment):
        return self.blind_store.getEntry(commitment)

    def getBlindBalances(self, pub_to=None, asset_id=None, used=None):
        query = [ ]
        if asset_id:
            query.append( ("asset_id", asset_id) )
        if not(used is None):
            query.append( ("used", int(used)) )
        if pub_to:
            query.append( ("pub_to", str(pub_to)) )
        return self.blind_store.getEntriesBy(query)

    def modifyBlindBalance(self, commitment, used):
        self.blind_store.updateEntryUsed(commitment, used)
