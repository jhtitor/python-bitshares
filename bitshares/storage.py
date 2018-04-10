import shutil
import time
import os
import sqlite3
import json
from .aes import AESCipher
from appdirs import user_data_dir
from datetime import datetime
import logging
from binascii import hexlify
import random
import hashlib
from .exceptions import WrongMasterPasswordException
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())

timeformat = "%Y%m%d-%H%M%S"


class DataDir(object):
    """ This class ensures that the user's data is stored in its OS
        preotected user directory:

        **OSX:**

         * `~/Library/Application Support/<AppName>`

        **Windows:**

         * `C:\\Documents and Settings\\<User>\\Application Data\\Local Settings\\<AppAuthor>\\<AppName>`
         * `C:\\Documents and Settings\\<User>\\Application Data\\<AppAuthor>\\<AppName>`

        **Linux:**

         * `~/.local/share/<AppName>`

         Furthermore, it offers an interface to generated backups
         in the `backups/` directory every now and then.
    """
    appname = "bitshares"
    appauthor = "Fabian Schuh"
    storageDatabaseDefault = "bitshares.sqlite"

    @classmethod
    def preflight(self, filename=True):
        """ Return potential user_dir (or full wallet path),
            without actually doing anything.
        """
        path = user_data_dir(self.appname, self.appauthor)
        if not filename:
            return path
        return os.path.join(path, self.storageDatabaseDefault)

    def __init__(self, path=None, mustexist=False):
        if not path:
            self.data_dir = user_data_dir(self.appname, self.appauthor)
            self.sqlDataBaseFile = os.path.join(self.data_dir, self.storageDatabaseDefault)
        else:
            self.data_dir = os.path.dirname(path)
            self.sqlDataBaseFile = path

        if mustexist and not(os.path.isdir(self.data_dir)):
            raise Exception("Not found")

        if mustexist and not(os.path.isfile(self.sqlDataBaseFile)):
            raise Exception("Not found")

        #: Storage
        self.mkdir_p()

    def mkdir_p(self):
        """ Ensure that the directory in which the data is stored
            exists
        """
        if os.path.isdir(self.data_dir):
            return
        else:
            try:
                os.makedirs(self.data_dir)
            except FileExistsError:
                return
            except OSError:
                raise

    def sqlite3_backup(self, dbfile, backupdir):
        """ Create timestamped database copy
        """
        if not os.path.isdir(backupdir):
            os.mkdir(backupdir)
        backup_file = os.path.join(
            backupdir,
            os.path.basename(self.storageDatabase) +
            datetime.now().strftime("-" + timeformat))
        connection = sqlite3.connect(self.sqlDataBaseFile)
        cursor = connection.cursor()
        # Lock database before making a backup
        cursor.execute('begin immediate')
        # Make new backup file
        shutil.copyfile(dbfile, backup_file)
        log.info("Creating {}...".format(backup_file))
        # Unlock database
        connection.rollback()
        self.configStorage["lastBackup"] = datetime.now().strftime(timeformat)

    def clean_data(self):
        """ Delete files older than 70 days
        """
        log.info("Cleaning up old backups")
        for filename in os.listdir(self.data_dir):
            backup_file = os.path.join(self.data_dir, filename)
            if os.stat(backup_file).st_ctime < (time.time() - 70 * 86400):
                if os.path.isfile(backup_file):
                    os.remove(backup_file)
                    log.info("Deleting {}...".format(backup_file))

    def refreshBackup(self):
        """ Make a new backup
        """
        backupdir = os.path.join(self.data_dir, "backups")
        self.sqlite3_backup(self.sqlDataBaseFile, backupdir)
        self.clean_data()

    def exists_table(self):
        """ Check if the database table exists
        """
        query = ("SELECT name FROM sqlite_master " +
                 "WHERE type='table' AND name=?",
                 (self.__tablename__, ))
        table = self.sql_fetchone(query)
        return True if table else False

    def sql_fetchone(self, query):
        connection = sqlite3.connect(self.sqlDataBaseFile)
        cursor = connection.cursor()
        cursor.execute(*query)
        result = cursor.fetchone()
        return result

    def sql_fetchall(self, query):
        connection = sqlite3.connect(self.sqlDataBaseFile)
        cursor = connection.cursor()
        cursor.execute(*query)
        results = cursor.fetchall()
        return results

    def sql_execute(self, query, lastid=False):
        connection = sqlite3.connect(self.sqlDataBaseFile)
        cursor = connection.cursor()
        cursor.execute(*query)
        connection.commit()
        if lastid:
            cursor = connection.cursor()
            cursor.execute("SELECT last_insert_rowid();")
            result = cursor.fetchone()
            return result[0]

    def sql_todict(self, columns, rows, merge=None):
        items = [ ]
        for row in rows:
            item = { }
            for i, key in enumerate(columns):
                item[key] = row[i]
                #if key.endswith('_json'):
                if merge and key in merge:
                     data = json.loads(row[i])
                     item[key] = data
                     for mkey in merge[key]:
                         item[mkey] = data[mkey]
            items.append(item)
        return items

class Key(DataDir):
    """ This is the key storage that stores the public key and the
        (possibly encrypted) private key in the `keys` table in the
        SQLite3 database.
    """
    __tablename__ = 'keys'

    def __init__(self, *args, **kwargs):
        super(Key, self).__init__(*args, **kwargs)

    def create_table(self):
        """ Create the new table in the SQLite database
        """
        query = ('CREATE TABLE %s (' % self.__tablename__ +
                 'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
                 'pub STRING(256),' +
                 'wif STRING(256)' +
                 ')',)
        self.sql_execute(query)

    def getPublicKeys(self):
        """ Returns the public keys stored in the database
        """
        query = ("SELECT pub from %s " % (self.__tablename__),)
        results = self.sql_fetchall(query)
        return [x[0] for x in results]

    def getPrivateKeyForPublicKey(self, pub):
        """ Returns the (possibly encrypted) private key that
            corresponds to a public key

           :param str pub: Public key

           The encryption scheme is BIP38
        """
        query = ("SELECT wif from %s " % (self.__tablename__) +
                 "WHERE pub=?",
                 (pub,))
        key = self.sql_fetchone(query)
        if key:
            return key[0]
        else:
            return None

    def updateWif(self, pub, wif):
        """ Change the wif to a pubkey

           :param str pub: Public key
           :param str wif: Private key
        """
        query = ("UPDATE %s " % self.__tablename__ +
                 "SET wif=? WHERE pub=?",
                 (wif, pub))
        self.sql_execute(query)

    def add(self, wif, pub):
        """ Add a new public/private key pair (correspondence has to be
            checked elsewhere!)

           :param str pub: Public key
           :param str wif: Private key
        """
        if self.getPrivateKeyForPublicKey(pub):
            raise ValueError("Key already in storage")
        query = ('INSERT INTO %s (pub, wif) ' % self.__tablename__ +
                 'VALUES (?, ?)',
                 (pub, wif))
        self.sql_execute(query)

    def delete(self, pub):
        """ Delete the key identified as `pub`

           :param str pub: Public key
        """
        query = ("DELETE FROM %s " % (self.__tablename__) +
                 "WHERE pub=?",
                 (pub,))
        self.sql_execute(query)

    def wipe(self, sure=False):
        """ Purge the entire wallet. No keys will survive this!
        """
        if not sure:
            log.error(
                "You need to confirm that you are sure "
                "and understand the implications of "
                "wiping your wallet!"
            )
            return
        else:
            query = ("DELETE FROM %s " % self.__tablename__,)
            self.sql_execute(query)


class Configuration(DataDir):
    """ This is the configuration storage that stores key/value
        pairs in the `config` table of the SQLite3 database.
    """
    __tablename__ = "config"

    #: Default configuration
    config_defaults = {
        "node": "wss://node.bitshares.eu",
        "rpcpassword": "",
        "rpcuser": "",
        "order-expiration": 7 * 24 * 60 * 60,
    }

    def __init__(self, *args, **kwargs):
        super(Configuration, self).__init__(*args, **kwargs)

    def create_table(self):
        """ Create the new table in the SQLite database
        """
        query = ('CREATE TABLE %s (' % self.__tablename__ +
                 'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
                 'key STRING(256),' +
                 'value STRING(256)' +
                 ')',)
        self.sql_execute(query)

    def checkBackup(self):
        """ Backup the SQL database every 7 days
        """
        if ("lastBackup" not in self.configStorage or
                self.configStorage["lastBackup"] == ""):
            print("No backup has been created yet!")
            self.refreshBackup()
        try:
            if (
                datetime.now() -
                datetime.strptime(self.configStorage["lastBackup"],
                                  timeformat)
            ).days > 7:
                print("Backups older than 7 days!")
                self.refreshBackup()
        except:
            self.refreshBackup()

    def _haveKey(self, key):
        """ Is the key `key` available int he configuration?
        """
        query = ("SELECT value FROM %s " % (self.__tablename__) +
                 "WHERE key=?",
                 (key,)
                 )
        connection = sqlite3.connect(self.sqlDataBaseFile)
        cursor = connection.cursor()
        cursor.execute(*query)
        return True if cursor.fetchone() else False

    def __getitem__(self, key):
        """ This method behaves differently from regular `dict` in that
            it returns `None` if a key is not found!
        """
        query = ("SELECT value FROM %s " % (self.__tablename__) +
                 "WHERE key=?",
                 (key,)
                 )
        result = self.sql_fetchone(query)
        if result:
            return result[0]
        else:
            if key in self.config_defaults:
                return self.config_defaults[key]
            else:
                return None

    def get(self, key, default=None):
        """ Return the key if exists or a default value
        """
        if key in self:
            return self.__getitem__(key)
        else:
            return default

    def __contains__(self, key):
        if self._haveKey(key) or key in self.config_defaults:
            return True
        else:
            return False

    def __setitem__(self, key, value):
        if self._haveKey(key):
            query = ("UPDATE %s " % self.__tablename__ +
                     "SET value=? WHERE key=?",
                     (value, key))
        else:
            query = ("INSERT INTO %s " % self.__tablename__ +
                     "(key, value) VALUES (?, ?)",
                     (key, value))
        self.sql_execute(query)

    def delete(self, key):
        """ Delete a key from the configuration store
        """
        query = ("DELETE FROM %s " % (self.__tablename__) +
                 "WHERE key=?",
                 (key,))
        self.sql_execute(query)

    def __iter__(self):
        return iter(self.items())

    def items(self):
        query = ("SELECT key, value from %s " % (self.__tablename__))
        connection = sqlite3.connect(self.sqlDataBaseFile)
        cursor = connection.cursor()
        cursor.execute(query)
        r = {}
        for key, value in cursor.fetchall():
            r[key] = value
        return r

    def __len__(self):
        query = ("SELECT id from %s " % (self.__tablename__))
        connection = sqlite3.connect(self.sqlDataBaseFile)
        cursor = connection.cursor()
        cursor.execute(query)
        return len(cursor.fetchall())


class MasterPassword(object):
    """ The keys are encrypted with a Masterpassword that is stored in
        the configurationStore. It has a checksum to verify correctness
        of the password
    """

    password = ""
    decrypted_master = ""

    #: This key identifies the encrypted master password stored in the confiration
    config_key = "encrypted_master_password"

    def __init__(self, configStorage, password):
        """ The encrypted private keys in `keys` are encrypted with a
            random encrypted masterpassword that is stored in the
            configuration.

            The password is used to encrypt this masterpassword. To
            decrypt the keys stored in the keys database, one must use
            BIP38, decrypt the masterpassword from the configuration
            store with the user password, and use the decrypted
            masterpassword to decrypt the BIP38 encrypted private keys
            from the keys storage!

            :param str password: Password to use for en-/de-cryption
        """
        self.configStorage = configStorage
        self.password = password
        if self.config_key not in self.configStorage:
            self.newMaster()
            self.saveEncrytpedMaster()
        else:
            self.decryptEncryptedMaster()

    def decryptEncryptedMaster(self):
        """ Decrypt the encrypted masterpassword
        """
        aes = AESCipher(self.password)
        checksum, encrypted_master = self.configStorage[self.config_key].split("$")
        try:
            decrypted_master = aes.decrypt(encrypted_master)
        except:
            raise WrongMasterPasswordException
        if checksum != self.deriveChecksum(decrypted_master):
            raise WrongMasterPasswordException
        self.decrypted_master = decrypted_master

    def saveEncrytpedMaster(self):
        """ Store the encrypted master password in the configuration
            store
        """
        self.configStorage[self.config_key] = self.getEncryptedMaster()

    def newMaster(self):
        """ Generate a new random masterpassword
        """
        # make sure to not overwrite an existing key
        if (self.config_key in self.configStorage and
                self.configStorage[self.config_key]):
            return
        self.decrypted_master = hexlify(os.urandom(32)).decode("ascii")

    def deriveChecksum(self, s):
        """ Derive the checksum
        """
        checksum = hashlib.sha256(bytes(s, "ascii")).hexdigest()
        return checksum[:4]

    def getEncryptedMaster(self):
        """ Obtain the encrypted masterkey
        """
        if not self.decrypted_master:
            raise Exception("master not decrypted")
        aes = AESCipher(self.password)
        return "{}${}".format(self.deriveChecksum(self.decrypted_master),
                              aes.encrypt(self.decrypted_master))

    def changePassword(self, newpassword):
        """ Change the password
        """
        self.password = newpassword
        self.saveEncrytpedMaster()

    @staticmethod
    def wipe(sure=False):
        if not sure:
            log.error(
                "You need to confirm that you are sure "
                "and understand the implications of "
                "wiping your wallet!"
            )
            return
        else:
            self.configStorage.delete(MasterPassword.config_key)


class BlindAccounts(DataDir):
    """
    """
    __tablename__ = 'blindaccounts'

    def __init__(self, *args, **kwargs):
        super(BlindAccounts, self).__init__(*args, **kwargs)

    def create_table(self):
        """ Create the new table in the SQLite database
        """
        query = ('CREATE TABLE %s (' % self.__tablename__ +
                 'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
                 'label STRING(256),' +
                 'pub STRING(256),' +
                 'graphene_json TEXT,' +
                 'balances_json TEXT,' +
                 'keys INTEGER'
                 ')', )
        self.sql_execute(query)

    def getAccounts(self):
        """ Returns all blind accounts stored in the database
        """
        query = ("SELECT label, pub from %s " % (self.__tablename__), )
        results = self.sql_fetchall(query)
        return results

    def getBy(self, key, some_id):
        """
        """
        if key not in ['label', 'pub']:
            raise KeyError("'key' must be label or pub")
        query = ("SELECT graphene_json, balances_json, label, pub from %s " % (self.__tablename__) +
                 "WHERE %s=?" % (key),
                 (some_id, ))
        connection = sqlite3.connect(self.sqlDataBaseFile)
        cursor = connection.cursor()
        cursor.execute(*query)
        row = cursor.fetchone()
        if not row:
            return None

        body = json.loads(row[0]) if row[0] else { }
        body['balances'] = json.loads(row[1]) if row[1] else { }
        body['label'] = row[2]
        body['pub'] = row[3]
        return body

    def getByPublicKey(self, pub):
        return self.getBy('pub', pub)

    def getByLabel(self, label):
        return self.getBy('label', label)

    def update(self, pub, key, val):
        """ Update blind account identified by `pub`lic key

           :param str pub: Public key
           :param str key: label, graphene_json or balances_json
           :param val: value to set
        """
        if not(key in ['label', 'graphene_json', 'balances_json']):
            raise ValueError("'key' must be graphene_json, balances_json or label")
        query = ("UPDATE %s " % self.__tablename__ +
                 ("SET %s=? WHERE pub=?" % key),
                 (json.dumps(val) if key != "label" else val, pub))
        self.sql_execute(query)

    def add(self, pub, label, keys=1):
        """ Add a blind account

           :param str pub: Public key
           :param str wif: Private key
           :param str label: Account name
        """
        if self.getByPublicKey(pub):
            raise ValueError("Account already in storage")
        query = ('INSERT INTO %s (pub, label, keys) ' % self.__tablename__ +
                 'VALUES (?, ?, ?)',
                 (pub, label, keys))
        self.sql_execute(query)

    def delete(self, pub):
        """ Delete the record identified by `pub`lic key

           :param str pub: Public key
        """
        query = ("DELETE FROM %s " % (self.__tablename__) +
                 "WHERE pub=?",
                 (pub))
        self.sql_execute(query)

class BlindHistory(DataDir):
    """ Store Blind Balances
    """
    __tablename__ = 'blindhistory'
    __columns__ = [
        'id', 'commitment', 'receipt',
        'amount', 'asset_id', 'used',
        'graphene_json', 'pub_from', 'pub_to',
        'description', 'date'
    ]
    __jsonmerge__ = {
        "graphene_json": [
            "control_authority",
            "blinding_factor",
        ]
    }

    def __init__(self, *args, **kwargs):
        super(BlindHistory, self).__init__(*args, **kwargs)

    def create_table(self):
        """ Create the new table in the SQLite database
        """
        query = ('CREATE TABLE %s (' % self.__tablename__ +
                 'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
                 'commitment STRING(512),' +
                 'receipt STRING(512),' +
                 'amount INTEGER,' +
                 'asset_id STRING(16),' +
                 'used INTEGER,' +
                 'graphene_json TEXT,' +
                # 'blinding_factor STRING(256),' +
                 'pub_from STRING(256),' +
                 'pub_to STRING(256),' +
                 'description STRING(512),' +
                 'date TEXT'
                 ')', )
        self.sql_execute(query)

    def getEntriesBy(self, column_value_pairs, glue_and=True):
        """ Returns all entries stored in the database
        """
        sql = ("SELECT * from %s WHERE " % self.__tablename__)
        data = [ ]
        sep = ""
        for column, value in column_value_pairs:
            sql += sep
            sql += ("%s = ? " % column)
            data.append( value )
            sep = "AND " if glue_and else "OR "
        query = (sql, data)
        rows = self.sql_fetchall(query)
        return self.sql_todict(self.__columns__, rows, self.__jsonmerge__)

    def getEntry(self, commitment):
        query = (("SELECT * from %s " % self.__tablename__) +
            "WHERE commitment=?",
            (commitment,)
        )
        row = self.sql_fetchone(query)
        if not row:
            return None
        return self.sql_todict(self.__columns__, [row], self.__jsonmerge__)[0]

    def add(self, commitment, balance):
        """ Add an entry

           :param str commitment: HEX commitment
           :param dict balance: dict with usable values
        """
        if self.getEntry(commitment):
            raise ValueError("Entry already in storage")

        query = ('INSERT INTO %s (' % self.__tablename__ +
                'commitment, receipt, pub_from, pub_to,'+
                'amount, asset_id,'+
                'graphene_json, used, description,'+
                'date'+
            ') ' +
           'VALUES (?,?,?,?,  ?,?,  ?,?,?, datetime(CURRENT_TIMESTAMP) )',
           (commitment, balance["receipt"], balance["from"], balance["to"],
            balance["amount"], balance["asset_id"],
            json.dumps(balance), int(balance["used"]), balance["description"],
            ))
        self.sql_execute(query)

    def update(self, commitment, key, value):
        if not(key in ['description']):
            raise ValueError("'key' must description")
        query = ("UPDATE %s " % self.__tablename__ +
                 "SET %s=? WHERE commitment=?" % key,
                 (value, commitment))
        self.sql_execute(query)

    def updateEntryUsed(self, commitment, used):
        query = ("UPDATE %s " % self.__tablename__ +
                 "SET used=? WHERE commitment=?",
                 (int(used), commitment))
        self.sql_execute(query)

    def deleteBy(self, column, value):
        """ Delete the record identified by `id`

           :param int id: Internal db id
        """
        if not column in self.__columns__:
            raise KeyError(column + " not a valid column")
        query = ("DELETE FROM %s " % (self.__tablename__) +
                 "WHERE %s=?" % (column),
                 (value))
        return self.sql_execute(query)

    def delete(self, commitment):
        """ Delete the record(s) identified by `commitment`
           :param str commitment: Blind commitment
        """
        return self.deleteBy('commitment', commitment)




class BitsharesStorage():

    def __init__(self, path=None, create=True):
        # Pick path from appdirs
        if path is None:
            path = DataDir.preflight(filename=True)

        # Create keyStorage
        self.keyStorage = Key(path, mustexist = not(create))
        self.configStorage = Configuration(path, mustexist = not(create))

        # Create Tables if database is brand new
        if not self.configStorage.exists_table() and create:
            self.configStorage.create_table()

        if not self.keyStorage.exists_table() and create:
            self.keyStorage.create_table()

        # Additional tables
        self.blindAccountStorage = BlindAccounts(path)
        if not self.blindAccountStorage.exists_table() and create:
            self.blindAccountStorage.create_table()

        self.blindStorage = BlindHistory(path)
        if not self.blindStorage.exists_table() and create:
            self.blindStorage.create_table()
