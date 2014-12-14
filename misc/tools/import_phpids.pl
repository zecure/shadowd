#!/usr/bin/perl

# Shadow Daemon -- Web Application Firewall
#
#   Copyright (C) 2014 Hendrik Buchwald <hb@zecure.org>
#
# This file is part of Shadow Daemon. Shadow Daemon is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;
use JSON;
use DBI;
use Getopt::Std;

my %opts;
getopts('hdui:N:H:U:P:D:', \%opts);

$opts{'D'} = 'Pg' unless ($opts{'D'});
$opts{'N'} = 'shadowd' unless ($opts{'N'});
$opts{'H'} = '127.0.0.1' unless ($opts{'H'});
$opts{'U'} = 'postgres' unless ($opts{'U'});
$opts{'P'} = '' unless ($opts{'P'});

# Connect to the database and prepare all statements.
my $dbh = DBI->connect(
	'dbi:' . $opts{'D'} . ':dbname=' . $opts{'N'} . ';host=' . $opts{'H'},
	$opts{'U'},
	$opts{'P'},
	{'RaiseError' => 1}
);

my $delete_filters = $dbh->prepare('DELETE FROM blacklist_filters');
my $update_filter = $dbh->prepare('UPDATE blacklist_filters SET rule_id = ?, impact = ?, description = ? WHERE id = ?');
my $insert_filter = $dbh->prepare('INSERT INTO blacklist_filters(id, rule_id, impact, description) VALUES(?, ?, ?, ?)');
my $select_filter = $dbh->prepare('SELECT COUNT(id) FROM blacklist_filters WHERE id = ?');
my $insert_tag = $dbh->prepare('INSERT INTO tags(tag) VALUES(?)');
my $select_tag = $dbh->prepare('SELECT id FROM tags WHERE tag = ?');
my $delete_tag_filter_connectors = $dbh->prepare('DELETE FROM tags_filters');
my $delete_tag_filter_connectors_by_filter = $dbh->prepare('DELETE FROM tags_filters WHERE filter_id = ?');
my $insert_tag_filter_connector = $dbh->prepare('INSERT INTO tags_filters(tag_id, filter_id) VALUES(?, ?)');
my $select_tag_filter_connector = $dbh->prepare('SELECT COUNT(id) FROM tags_filters WHERE tag_id = ? AND filter_id = ?');

sub import_filter {
	my $filter = shift;
	my $update = shift;

	# Create an array with all tags for this filter.
	my @tags;

	# json_tags can either be an array of strings or a single string.
	my $json_tags = $filter->{'tags'}->{'tag'};

	if (ref($json_tags) eq 'ARRAY') {
		@tags = @{$json_tags};
	} else {
		push(@tags, $json_tags);
	}

	# Check if filter with the id exists.
	$select_filter->execute($filter->{'id'});
	my $filter_exists = $select_filter->fetchrow_array();

	if ($filter_exists && !$update) {
		return;
	} elsif ($filter_exists && $update) {
		$update_filter->execute(
			$filter->{'rule'},
			$filter->{'impact'},
			$filter->{'description'},
			$filter->{'id'}
		);
	} else {
		$insert_filter->execute(
			$filter->{'id'},
			$filter->{'rule'},
			$filter->{'impact'},
			$filter->{'description'}
		);
	}

	# Clear all existing tag_filter_connectors if there are any.
	$delete_tag_filter_connectors_by_filter->execute($filter->{'id'});

	# Iterate over tags and add them to this filter.
	foreach my $tag (@tags) {
		# If tag already is in the database get the existing id, otherwise insert it.
		$select_tag->execute($tag);
		my $tag_id = $select_tag->fetchrow_array();

		unless ($tag_id) {
			$insert_tag->execute($tag);
			$tag_id = $dbh->last_insert_id(undef, undef, 'tags', undef);
		}

		# Add connector for tag and filter if there is none.
		$select_tag_filter_connector->execute($tag_id, $filter->{'id'});
		my $connector_exists = $select_tag_filter_connector->fetchrow_array();
		$insert_tag_filter_connector->execute($tag_id, $filter->{'id'}) unless ($connector_exists);
	}
}

sub import_phpids {
	my $file = shift;
	my $update = shift;

	# Read in the complete file and save it as a string.
	local $/= undef;
	open FILE, $file or die "Couldn't open file: $!";
	my $content = <FILE>;
	close FILE;

	# Decode the json string.
	my $json = JSON->new->allow_nonref;
	my $json_decoded = $json->decode($content);

	# Iterate over all filters and import them.
	my @filters = @{$json_decoded->{'filters'}->{'filter'}};

	foreach my $filter (@filters) {
		import_filter($filter, $update);
	}
}

sub delete_filters {
	$delete_tag_filter_connectors->execute();
	$delete_filters->execute();
}

sub help {
	print "Shadow Daemon -- Web Application Firewall\n" .
	 "PHPIDS default_filter.json Database Importer\n" .
	 "usage: " . $0 . " [options]\n" .
	 "  -i <file>: Path to input file\n" .
	 "  -u: Update existing filters\n" .
	 "  -d: Delete all existing filters\n" .
	 "  -D <driver>: Database driver\n" .
	 "  -N <name>: Database name\n" .
	 "  -H <host>: Database host\n" .
	 "  -U <user>: Database user\n" .
	 "  -P <password>: Database password\n";	  

	exit;
}

help() if (($opts{'h'}) || (!$opts{'d'} && !$opts{'i'}));
delete_filters() if ($opts{'d'});
import_phpids($opts{'i'}, $opts{'u'}) if ($opts{'i'});
