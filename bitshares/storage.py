from graphenestorage import (
    InRamConfigurationStore,
    InRamPlainKeyStore,
    InRamEncryptedKeyStore,
    SqliteConfigurationStore,
    SqlitePlainKeyStore,
    SqliteEncryptedKeyStore,
    SQLiteFile, SQLiteCommon
)

class SQLiteExtendedStore(SQLiteFile, SQLiteCommon):
    """ The SQLiteExtendedStore deals with the sqlite3 part of storing data into a
        database file.

        .. note:: This module is not limited to two columns 

        On first launch, the database file as well as the tables are created
        automatically.

        When inheriting from this class, the following class members must
        be defined:

            * ``__tablename__``: Name of the table
            * ``__columns__``: Names of the columns
    """

    #:
    __tablename__ = None
    __columns__ = None

    def __init__(self, *args, **kwargs):
        #: Storage
        SQLiteFile.__init__(self, *args, **kwargs)
        #StoreInterface.__init__(self, *args, **kwargs)
        if (
            self.__tablename__ is None or
            self.__columns__ is None
        ):
            raise ValueError(
                "Values missing for tablename or columns!"
            )
        if not self.exists():  # pragma: no cover
            self.create()
        else:
            self.upgrade()

    def __len__(self):
        """ return lenght of store
        """
        query = ("SELECT COUNT({}) from {}".format(self.__columns__[0], self.__tablename__), )
        return self.sql_fetchone(query)[0]

    def wipe(self):
        """ Wipe the store
        """
        query = "DELETE FROM {}".format(self.__tablename__)
        self.sql_execute(query)

    def exists(self):
        """ Check if the database table exists
        """
        query = ("SELECT name FROM sqlite_master " +
                 "WHERE type='table' AND name=?",
                 (self.__tablename__, ))
        return True if self.sql_fetchone(query) else False

    def create(self):  # pragma: no cover
        """ Create new database table.
            This MUST be implemented by inheriting classes.
        """
        raise NotImplementedError

    def upgrade(self):
        """ Upgrade the database table, if needed
        """
        pass

    def deleteBy(self, column, value):
        """ Delete the record identified by `column` = `value`

           :param str column: Name of the column
           :param str value: Value
        """
        if not column in self.__columns__:
            raise KeyError(column + " not a valid column")
        query = ("DELETE FROM {} ".format(self.__tablename__) +
                 "WHERE {}=?".format(column),
                 (value,))
        return self.sql_execute(query)

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


class BlindCommitmentsInterface(object):
    pass

class SqliteBlindHistoryStore(
    SQLiteExtendedStore,
    BlindCommitmentsInterface
):
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
        super(SqliteBlindHistoryStore, self).__init__(*args, **kwargs)

    def create(self):
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

    def delete(self, commitment):
        """ Delete the record(s) identified by `commitment`

           :param str commitment: Blind commitment
        """
        return self.deleteBy('commitment', commitment)



url = "wss://node.bitshares.eu"
InRamConfigurationStore.setdefault("node", url)
SqliteConfigurationStore.setdefault("node", url)


def get_default_config_store(*args, **kwargs):
    if "appname" not in kwargs:
        kwargs["appname"] = "bitshares"
    return SqliteConfigurationStore(*args, **kwargs)


def get_default_key_store(config, *args, **kwargs):
    if "appname" not in kwargs:
        kwargs["appname"] = "bitshares"
    return SqliteEncryptedKeyStore(
        config=config, **kwargs
    )

def get_default_blind_store(*args, **kwargs):
    if "appname" not in kwargs:
        kwargs["appname"] = "bitshares"
    return SqliteBlindHistoryStore(**kwargs)
