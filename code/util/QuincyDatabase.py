import os.path
import logging
from datetime import datetime

from gridfs import GridFS
from pymongo import MongoClient, ASCENDING

from QuincyConfig import dbconfig
from QuincyUtils import getHash

class NoSuchDumpError(Exception):
    pass


class DuplicateDocumentError(Exception):
    pass


class Database(object):
    """ Class to manage manipulations of the database for
        the basic sample and result framework.

        Keyword arguments:
        hostname -- the hostname of the mongod instance (default: 'localhost')
        port -- the port of the mongod instance (default: 27017)
        database -- the name of the database to be used (default: 'winXP')
    """

    def __init__(self, hostname='localhost', port=27017, db_name='winXP'):
        logging.info("Init database module")
        self._client = MongoClient(hostname, port)
        self._database = self._client.get_database(db_name)
        self._samplesFs = GridFS(self._database, dbconfig['sampleFsCollectionName'])
        self._samples = self._database[dbconfig['sampleCollectionName']]
        self._results = self._database[dbconfig['resultCollectionName']]
        self._dumps = self._database[dbconfig['dumpCollectionName']]

    def addSample(self, path, classification, overwrite=False):
        """ Feeds a single sample to the database, if it
            is not already contained in it.

            Keyword arguments:
            path -- the path to the binary
        """
        name = os.path.split(path)[1]
        if '.' in name:
            name = name.split('.')[0]
        with open(path, 'rb') as binary:
            raw = binary.read()
        entry = {
            '_id': getHash(raw),
            'path': path,
            'name': name,
            'timestamp': datetime.now(),
            'classification': classification,
            'raw': self._samplesFs.put(raw)
        }
        if overwrite:
            self._samples.replace_one({'_id': entry['_id']}, entry, upsert=True)
        else:
            if not self._samples.find_one({'_id': entry['_id']}):
                self._samples.insert_one(entry)
            else:
                logging.info('Skipping sample "%s" (already in database)' % path)
                return False
        return True

    def addResult(self, entry):
        """ Add a result to the database.

            Keyword arguments:
            info -- dict containing the results and metadata
        """
        entry['timestamp'] = datetime.now()
        try:
            if self.getResult(entry['features']):
                raise DuplicateDocumentError('Result already in database:\n%s' % str(entry))
        except NoSuchDumpError:
            pass
        self._results.insert_one(entry)

    def addDumpInfo(self, entry, overwrite=False):
        """ Add a dump info to the database.

            Keyword arguments:
            info -- dict the metadata for the dump
        """
        entry['timestamp'] = datetime.now()

        if overwrite:
            self._dumps.save(entry)
        else:
            if not self.dumpExists(entry['_id']):
                self._dumps.insert_one(entry)

    def removeDumpInfo(self, _id):
        """ Removes the dump with the given id.

            Keyword arguments:
            id -- the id of the dump to remove
        """
        self._dumps.remove({'_id': _id})

    def removeSample(self, hashVal):
        """ Removes the sample with the given hash.

            Keyword arguments:
            hashVal -- the hash value of the sample
        """
        self._samples.remove({'_id': hashVal})

    def dumpExists(self, _id):
        try:
            self.getDumpInfo(_id)
            return True
        except NoSuchDumpError:
            return False

    def addGroundTruthToDump(self, dumpInfo, infected):
        """ Adds feature values to a dump entry.

            Keyword arguments:
            dumpInfo -- the entry to be updated
            results -- the dict to be set as results
        """
        update = {'$set': {'infected': infected}}
        self._dumps.update_one({'_id': dumpInfo['_id']}, update)

    def addDumpResults(self, dumpInfo, results):
        """ Adds feature values to a dump entry.

            Keyword arguments:
            dumpInfo -- the entry to be updated
            results -- the dict to be set as results
        """
        update = {'$set': {'results': results}}
        self._dumps.update_one({'_id': dumpInfo['_id']}, update)

    def getSample(self, hashVal):
        """ Returns a sample with the given sha 256 hash from
            the database with its metadata.

            Keyword arguments:
            hashVal -- the hash of the sample to be retrieved
        """
        sample = self._samples.find_one({'_id': hashVal})
        if sample and self._samplesFs.exists(sample['raw']):
            return sample
        raise ValueError('Can not find sample "%s" in database.' % hashVal)

    def getSampleBinary(self, _id):
        """ Returns the binary test_data of the given sample. """
        return self._samplesFs.get(_id).read()

    def getSamples(self, classification):
        """ Returns all samples of the given category.

            infected -- whenever benign or malicious samples are considered.
        """
        query = {'classification': classification}
        samples = self._samples.find(query, no_cursor_timeout=True)
        return samples.sort('name', ASCENDING)

    def getResult(self, features):
        """ Returns the results for the given combination of
            operating system and features.

            features -- the featurecombination in the result
        """
        result = self._results.find_one({'features': features})
        if result:
            return result
        raise NoSuchDumpError('Can not find a result for %r.' % (features,))

    def getResultAmount(self):
        """ Returns the amount of finished evaluations. """
        return self._results.find().count()

    def getDumpInfo(self, sampleHash):
        """ Returns the dump info for the given sample hash.

            Keyword arguments:
            sampleHash -- the sha256 hash of the sample
        """
        dump = self._dumps.find_one({'_id': sampleHash})
        if dump:
            return dump
        raise NoSuchDumpError('Can not find dump for "%s".' % sampleHash)

    def iterSamples(self):
        """ Iterates over all samples contained in the database. """
        for hashVal in self._samples.distinct('_id'):
            yield self.getSample(hashVal)

    def iterDumps(self):
        """ Iterates over all dump infos contained in the database. """
        for hashVal in self._dumps.distinct('_id'):
            yield self.getDumpInfo(hashVal)

    def iterIncompleteDumps(self, characteristics):
        """ Iterates over all dump infos contained in the database,
            which do not contain feature values.
        """
        query = []
        for char in characteristics:
            query.append({'results.%s' % char: {'$exists': False}})
        for info in self._dumps.find({'$or': query}, no_cursor_timeout=True):
            yield info

    def iterResults(self):
        """ Iterates over all dump infos contained in the database,
            which do not contain feature values.
        """
        for features in self._results.distinct('features'):
            yield self.getResult(features)

    def getBackup(self, host, suffix='backup'):
        """ Copies the current database to another host. """
        dbname = self._database.name
        self._client.admin.command('copydb',
                                   fromdb=dbname,
                                   todb=dbname + '_%s' % suffix,
                                   fromhost=host)
