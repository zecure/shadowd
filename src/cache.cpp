/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2015 Hendrik Buchwald <hb@zecure.org>
 *
 * This file is part of Shadow Daemon. Shadow Daemon is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#include "cache.h"

swd::cache::cache(swd::database_ptr database) :
 database_(database) {
}

swd::profile_ptr swd::cache::get_profile(std::string server_ip, int profile_id) {
	boost::unique_lock<boost::mutex> scoped_lock(profiles_mutex_);

	swd::tuple_is key = std::make_tuple(profile_id, server_ip);

	if (profiles_.find(key) != profiles_.end()) {
		return profiles_[key];
	}

	swd::profile_ptr profile = database_->get_profile(server_ip, profile_id);
	profiles_[key] = profile;

	return profile;
}

swd::blacklist_rules swd::cache::get_blacklist_rules(int profile_id,
 std::string caller, std::string path) {
	boost::unique_lock<boost::mutex> scoped_lock(blacklist_rules_mutex_);

	swd::tuple_iss key = std::make_tuple(profile_id, caller, path);

	if (blacklist_rules_.find(key) != blacklist_rules_.end()) {
		return blacklist_rules_[key];
	}

	swd::blacklist_rules blacklist_rules =
	 database_->get_blacklist_rules(profile_id, caller, path);

	/**
	 * Don't store non-existent results, otherwise memory could be filled with
	 * garbage by malicious clients via the path input.
	 */
	if (!blacklist_rules.empty()) {
		blacklist_rules_[key] = blacklist_rules;
	}

	return blacklist_rules;
}

swd::blacklist_filters swd::cache::get_blacklist_filters() {
	boost::unique_lock<boost::mutex> scoped_lock(blacklist_filters_mutex_);

	if (!blacklist_filters_.empty()) {
		return blacklist_filters_;
	}

	blacklist_filters_ = database_->get_blacklist_filters();

	return blacklist_filters_;
}

swd::whitelist_rules swd::cache::get_whitelist_rules(int profile_id,
 std::string caller, std::string path) {
	boost::unique_lock<boost::mutex> scoped_lock(whitelist_rules_mutex_);

	swd::tuple_iss key = std::make_tuple(profile_id, caller, path);

	if (whitelist_rules_.find(key) != whitelist_rules_.end()) {
		return whitelist_rules_[key];
	}

	swd::whitelist_rules whitelist_rules =
	 database_->get_whitelist_rules(profile_id, caller, path);

	if (!whitelist_rules.empty()) {
		whitelist_rules_[key] = whitelist_rules;
	}

	return whitelist_rules;
}

swd::integrity_rules swd::cache::get_integrity_rules(int profile_id,
 std::string caller) {
	boost::unique_lock<boost::mutex> scoped_lock(integrity_rules_mutex_);

	swd::tuple_is key = std::make_tuple(profile_id, caller);

	if (integrity_rules_.find(key) != integrity_rules_.end()) {
		return integrity_rules_[key];
	}

	swd::integrity_rules integrity_rules =
	 database_->get_integrity_rules(profile_id, caller);

	if (!integrity_rules.empty()) {
		integrity_rules_[key] = integrity_rules;
	}

	return integrity_rules;
}
