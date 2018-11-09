from graphenestorage.exceptions import WrongMasterPasswordException
from graphenestorage.exceptions import WalletLocked
from graphenestorage.exceptions import KeyAlreadyInStoreException


class WalletExists(Exception):
    """ A wallet has already been created and requires a password to be
        unlocked by means of :func:`bitshares.wallet.unlock`.
    """
    pass


class RPCConnectionRequired(Exception):
    """ An RPC connection is required
    """
    pass


class AccountExistsException(Exception):
    """ The requested account already exists
    """
    pass


class AccountDoesNotExistsException(Exception):
    """ The account does not exist
    """
    pass


class AssetDoesNotExistsException(Exception):
    """ The asset does not exist
    """
    pass


class InvalidAssetException(Exception):
    """ An invalid asset has been provided
    """
    pass


class InsufficientAuthorityError(Exception):
    """ The transaction requires signature of a higher authority
    """
    pass


class MissingKeyError(Exception):
    """ A required key couldn't be found in the wallet
    """
    pass


class InvalidWifError(Exception):
    """ The provided private Key has an invalid format
    """
    pass


class ProposalDoesNotExistException(Exception):
    """ The proposal does not exist
    """
    pass


class BlockDoesNotExistsException(Exception):
    """ The block does not exist
    """
    pass


class NoWalletException(Exception):
    """ No Wallet could be found, please use :func:`bitshares.wallet.create` to
        create a new wallet
    """
    pass


class WitnessDoesNotExistsException(Exception):
    """ The witness does not exist
    """
    pass


class CommitteeMemberDoesNotExistsException(Exception):
    """ Committee Member does not exist
    """
    pass


class VestingBalanceDoesNotExistsException(Exception):
    """ Vesting Balance does not exist
    """
    pass


class WorkerDoesNotExistsException(Exception):
    """ Worker does not exist
    """
    pass


class ObjectNotInProposalBuffer(Exception):
    """ Object was not found in proposal
    """
    pass


class InvalidMessageSignature(Exception):
    """ The message signature does not fit the message
    """
    pass


class KeyNotFound(Exception):
    """ Key not found
    """
    pass


class InvalidMemoKeyException(Exception):
    """ Memo key in message is invalid
    """
    pass


class OfflineHasNoRPCException(Exception):
    """ When in offline mode, we don't have RPC
    """
    pass


class WrongMemoKey(Exception):
    """ The memo provided is not equal the one on the blockchain
    """
    pass


class InsufficientBalance(Exception):
    """ Insufficient Balance
    """
    pass

class InsufficientBlindBalance(InsufficientBalance):
    """ Insufficient Blind Balance
    """
    def __init__(self, *args, **kwargs):
        self.input_adjust = kwargs.pop("input_adjust", 0)
        self.asset_obj = kwargs.pop("asset_obj", None)
        super(InsufficientBlindBalance, self).__init__(*args, **kwargs)
