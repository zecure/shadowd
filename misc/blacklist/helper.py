#!/usr/bin/env python
# Shadow Daemon -- Web Application Firewall
#
# Copyright (C) 2014-2022 Hendrik Buchwald <hb@zecure.org>
#
# This file is part of Shadow Daemon. Shadow Daemon is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
import sys
import os
import re

# Command line parameters
parser = argparse.ArgumentParser(description='Little blacklist helper')
parser.add_argument('--filters', '-f', default='filters.json')
parser.add_argument('--test', '-t', action='store_true')
parser.add_argument('--insert', '-i', action='store_true')
parser.add_argument('--compare', '-c', action='store_true')
parser.add_argument('--driver', default='pgsql')
parser.add_argument('--database', default='shadowd')
parser.add_argument('--username', default='shadowd')
parser.add_argument('--password', default='')

args = parser.parse_args()

# Use path of script as base
os.chdir(os.path.dirname(sys.argv[0]))

# Open blacklist filters
with open(args.filters) as data_file:    
    filters = json.load(data_file)

if args.test:
    error = False

    for filter in filters:
        try:
            rule = re.compile(filter['rule'], flags=re.I|re.S)

            if not 'examples' in filter:
                print('Filter ' + filter['id'] + ' missing examples')
                continue

            for example in filter['examples']:
                if not rule.search(example):
                    raise
        except:
            print('Filter ' + filter['id'] + ' failed')
            error = True

    if error:
        print('Test failed')
        sys.exit(1)
    else:
        print('Test succeeded')
        sys.exit(0)
elif args.insert:
    if args.driver == 'mysql':
        import MySQLdb.cursors

        db = MySQLdb.connect(host='localhost', db=args.database,
                             user=args.username, passwd=args.password)
    elif args.driver == 'pgsql':
        import psycopg2

        db = psycopg2.connect(host='localhost', database=args.database,
                              user=args.username, password=args.password)
    else:
        raise

    cur = db.cursor()

    for filter in filters:
        cur.execute("INSERT INTO blacklist_filters (id, rule, impact, description) values (%s, %s, %s, %s)",
                    (filter['id'], filter['rule'], filter['impact'], filter['description']))

        for tag in filter['tags']:
            cur.execute("INSERT INTO tags_filters (tag_id, filter_id) VALUES ((SELECT id FROM tags WHERE tag = %s), %s)",
                        (tag, filter['id']))
    db.commit()

elif args.compare:
    pass
