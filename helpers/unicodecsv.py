# Purpose:  CSV utilities

try:
    import cStringIO
except ImportError:
    # import will fail on py3, but that's not a problem
    pass
import sys
import codecs
import csv
import logging

from veracodetocsv.helpers.exceptions import VeracodeError


class UnicodeWriter:
    """A CSV writer which will write rows to CSV file "f", which is encoded in the given encoding."""
    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwargs):
        # Redirect output to a queue
        self.queue = cStringIO.StringIO()
        self.writer = csv.writer(self.queue, dialect=dialect, **kwargs)
        self.stream = f
        self.encoder = codecs.getincrementalencoder(encoding)()

    def writerow(self, row):
        self.writer.writerow([s.encode("utf-8") if hasattr(s, "encode") else s for s in row])
        # Fetch UTF-8 output from the queue ...
        data = self.queue.getvalue()
        data = data.decode("utf-8")
        # ... and reencode it into the target encoding
        data = self.encoder.encode(data)
        # write to the target stream
        self.stream.write(data)
        # empty queue
        self.queue.truncate(0)

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def create_csv(row_list, filepath):
    """Create a new CSV file from a list of rows."""
    try:
        with open(filepath, 'w') as f:
            if sys.version_info >= (3,):
                wr = csv.writer(f, quoting=csv.QUOTE_ALL, escapechar='\\')
            else:
                wr = UnicodeWriter(f, quoting=csv.QUOTE_ALL, escapechar='\\')
            wr.writerows(row_list)
    except IOError as e:
        logging.exception("Error writing csv file")
        raise VeracodeError(e)
