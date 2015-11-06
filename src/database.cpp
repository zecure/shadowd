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

#include <sstream>
#include <stdio.h>
#include <string.h>
#include <boost/lexical_cast.hpp>

#include "database.h"
#include "log.h"

void swd::database::connect(std::string driver, std::string host, std::string port,
 std::string username, std::string password, std::string name, std::string encoding) {
	driver_ = driver;

#if defined(HAVE_DBI_NEW)
	dbi_initialize_r(NULL, &instance_);
	conn_ = dbi_conn_new_r(driver.c_str(), instance_);
#else
	dbi_initialize(NULL);
	conn_ = dbi_conn_new(driver.c_str());
#endif

	dbi_conn_set_option(conn_, "host", host.c_str());
	dbi_conn_set_option(conn_, "port", port.c_str());
	dbi_conn_set_option(conn_, "username", username.c_str());
	dbi_conn_set_option(conn_, "password", password.c_str());
	dbi_conn_set_option(conn_, "dbname", name.c_str());
	dbi_conn_set_option(conn_, "encoding", encoding.c_str());

	/* If the initial connection can not be established the process is shut down. */
	if (dbi_conn_connect(conn_) < 0) {
		throw swd::exceptions::core_exception("Can't connect to database server");
	}
}

void swd::database::disconnect() {
	dbi_conn_close(conn_);
#if defined(HAVE_DBI_NEW)
	dbi_shutdown_r(instance_);
#endif
}

void swd::database::ensure_connection() {
	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	if (dbi_conn_ping(conn_) < 1) {
		swd::log::i()->send(swd::notice, "Dropped database connection");

		if (dbi_conn_connect(conn_) < 0) {
			throw swd::exceptions::database_exception("Lost database connection");
		}
	}
}

swd::profile_ptr swd::database::get_profile(std::string server_ip, int profile_id) {
	swd::log::i()->send(swd::notice, "Get profile -> server_ip: " + server_ip
	 + "; profile_id: " + boost::lexical_cast<std::string>(profile_id));

	/* Test the database connection status. Tries to reconnect if disconnected. */
	ensure_connection();

	/* Mutex to avoid race conditions. */
	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	/**
	 * First we escape server_ip. It comes from a trusted source, but better safe
	 * than sorry. This does not work with std::string though.
	 */
	char *server_ip_esc = strdup(server_ip.c_str());
	dbi_conn_quote_string(conn_, &server_ip_esc);

	/* Insert the ip and execute the query. */
	dbi_result res = dbi_conn_queryf(conn_, "SELECT id, hmac_key, mode, "
	 "whitelist_enabled, blacklist_enabled, integrity_enabled, flooding_enabled, "
	 "blacklist_threshold FROM profiles WHERE %s LIKE prepare_wildcard(server_ip) "
	 "AND id = %i", server_ip_esc, profile_id);

	/* Don't forget to free server_ip_esc to avoid a memory leak. */
	free(server_ip_esc);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute profile query");
	}

	if (dbi_result_get_numrows(res) != 1) {
		throw swd::exceptions::database_exception("Can't get profile");
	}

	if (!dbi_result_next_row(res)) {
		throw swd::exceptions::database_exception("No profile?");
	}

	swd::profile_ptr profile(
		new swd::profile(
			server_ip,
			dbi_result_get_uint(res, "id"),
			dbi_result_get_uint(res, "mode"),
			(dbi_result_get_uint(res, "whitelist_enabled") == 1),
			(dbi_result_get_uint(res, "blacklist_enabled") == 1),
			(dbi_result_get_uint(res, "integrity_enabled") == 1),
			(dbi_result_get_uint(res, "flooding_enabled") == 1),
			dbi_result_get_string(res, "hmac_key"),
			dbi_result_get_uint(res, "blacklist_threshold")
		)
	);

	dbi_result_free(res);

	return profile;
}

swd::blacklist_rules swd::database::get_blacklist_rules(int profile,
 std::string caller, std::string path) {
	swd::log::i()->send(swd::notice, "Get blacklist rules");

	ensure_connection();

	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	char *caller_esc = strdup(caller.c_str());
	dbi_conn_quote_string(conn_, &caller_esc);

	char *path_esc = strdup(path.c_str());
	dbi_conn_quote_string(conn_, &path_esc);

	dbi_result res = dbi_conn_queryf(conn_, "SELECT r.id, r.path, r.threshold "
	 "FROM blacklist_rules AS r WHERE r.profile_id = %i AND %s LIKE "
	 "prepare_wildcard(r.caller) AND %s LIKE prepare_wildcard(r.path) AND r.status = %i",
	 profile, caller_esc, path_esc, STATUS_ACTIVATED);

	free(caller_esc);
	free(path_esc);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute blacklist_rules query");
	}

	swd::blacklist_rules rules;

	while (dbi_result_next_row(res)) {
		swd::blacklist_rule_ptr rule(
			new swd::blacklist_rule(
				dbi_result_get_uint(res, "id"),
				dbi_result_get_uint(res, "threshold")
			)
		);

		rules.push_back(rule);
	}

	dbi_result_free(res);

	return rules;
}

swd::blacklist_filters swd::database::get_blacklist_filters() {
	swd::log::i()->send(swd::notice, "Get blacklist filters");

	ensure_connection();

	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	dbi_result res = dbi_conn_query(conn_, "SELECT id, rule, impact FROM blacklist_filters");

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute blacklist_filters query");
	}

	swd::blacklist_filters filters;

	while (dbi_result_next_row(res)) {
		swd::blacklist_filter_ptr filter(
			new swd::blacklist_filter(
				dbi_result_get_uint(res, "id"),
				dbi_result_get_string(res, "rule"),
				dbi_result_get_uint(res, "impact")
			)
		);

		filters.push_back(filter);
	}

	dbi_result_free(res);

	return filters;
}

swd::whitelist_rules swd::database::get_whitelist_rules(int profile,
 std::string caller, std::string path) {
	swd::log::i()->send(swd::notice, "Get whitelist rules");

	ensure_connection();

	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	char *caller_esc = strdup(caller.c_str());
	dbi_conn_quote_string(conn_, &caller_esc);

	char *path_esc = strdup(path.c_str());
	dbi_conn_quote_string(conn_, &path_esc);

	/**
	 * Remove LIKE single character wildcard, because it could result easily in security
	 * problems if a user forgets to escape an underscore. And instead of a percentage sign
	 * it is nicer to use an asterisk, because it is more common.
	 */
	dbi_result res = dbi_conn_queryf(conn_, "SELECT r.id, r.path, f.id as filter_id, "
	 "f.rule, f.impact, r.min_length, r.max_length FROM whitelist_rules AS r, "
	 "whitelist_filters AS f WHERE r.filter_id = f.id AND r.profile_id = %i AND %s LIKE "
	 "prepare_wildcard(r.caller) AND %s LIKE prepare_wildcard(r.path) AND r.status = %i",
	 profile, caller_esc, path_esc, STATUS_ACTIVATED);

	free(caller_esc);
	free(path_esc);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute whitelist_rules query");
	}

	swd::whitelist_rules rules;

	while (dbi_result_next_row(res)) {
		swd::whitelist_filter_ptr filter(
			new swd::whitelist_filter(
				dbi_result_get_uint(res, "filter_id"),
				dbi_result_get_string(res, "rule")
			)
		);

		swd::whitelist_rule_ptr rule(
			new swd::whitelist_rule(
				dbi_result_get_uint(res, "id"),
				filter,
				dbi_result_get_uint(res, "min_length"),
				dbi_result_get_uint(res, "max_length")
			)
		);

		rules.push_back(rule);
	}

	dbi_result_free(res);

	return rules;
}

int swd::database::save_request(int profile, std::string caller, std::string resource,
 int mode, std::string client_ip) {
	swd::log::i()->send(swd::notice, "Save request -> profile: "
	 + boost::lexical_cast<std::string>(profile) + "; caller: " + caller + "; resource: "
	 + resource + "; mode: " + boost::lexical_cast<std::string>(mode)
	 + "; client_ip: " + client_ip);

	ensure_connection();

	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	char *caller_esc = strdup(caller.c_str());
	dbi_conn_quote_string(conn_, &caller_esc);

	char *resource_esc = strdup(resource.c_str());
	dbi_conn_quote_string(conn_, &resource_esc);

	char *client_ip_esc = strdup(client_ip.c_str());
	dbi_conn_quote_string(conn_, &client_ip_esc);

	dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO requests (profile_id, "
	 "caller, resource, mode, client_ip, total_integrity_rules) VALUES (%i, %s, "
	 "%s, %i, %s, -1)", profile, caller_esc, resource_esc, mode, client_ip_esc);

	free(caller_esc);
	free(resource_esc);
	free(client_ip_esc);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute request query");
	}

	int id = dbi_conn_sequence_last(conn_, "requests_id_seq");

	dbi_result_free(res);

	return id;
}

int swd::database::save_parameter(int request, std::string path, std::string value,
 int total_whitelist_rules, int critical_impact, int threat) {
	ensure_connection();

	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	char *path_esc = strdup(path.c_str());
	dbi_conn_quote_string(conn_, &path_esc);

	char *value_esc = strdup(value.c_str());
	dbi_conn_quote_string(conn_, &value_esc);

	dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO parameters (request_id, "
	 "path, value, total_whitelist_rules, critical_impact, threat) VALUES (%i, %s, %s, %i, %i, %i)",
	 request, path_esc, value_esc, total_whitelist_rules, critical_impact, threat);

	free(path_esc);
	free(value_esc);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute parameter query");
	}

	int id = dbi_conn_sequence_last(conn_, "parameters_id_seq");

	dbi_result_free(res);

	return id;
}

void swd::database::add_blacklist_parameter_connector(int filter, int parameter) {
	ensure_connection();

	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO blacklist_parameters "
	 "(filter_id, parameter_id) VALUES (%i, %i)", filter, parameter);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute blacklist_parameter query");
	}
}

void swd::database::add_whitelist_parameter_connector(int rule, int parameter) {
	ensure_connection();

	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO whitelist_parameters "
	 "(rule_id, parameter_id) VALUES (%i, %i)", rule, parameter);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute whitelist_parameter query");
	}
}

bool swd::database::is_flooding(std::string client_ip, int profile_id) {
	ensure_connection();

	boost::unique_lock<boost::mutex> scoped_lock(dbi_mutex_);

	char *client_ip_esc = strdup(client_ip.c_str());
	dbi_conn_quote_string(conn_, &client_ip_esc);

	dbi_result res;

	if (driver_ == "pgsql") {
		res = dbi_conn_queryf(conn_, "SELECT 1 FROM (SELECT COUNT(requests.id) "
		 "AS request_count FROM requests WHERE requests.mode != 3 AND "
		 "requests.client_ip = %s AND requests.profile_id = %i AND requests.date "
		 "> NOW() - ((SELECT profiles.flooding_timeframe FROM profiles WHERE profiles.id "
		 "= %i) || ' second')::INTERVAL) r WHERE r.request_count >= (SELECT "
		 "profiles.flooding_threshold FROM profiles WHERE profiles.id = %i)",
		 client_ip_esc, profile_id, profile_id, profile_id);
	} else if (driver_ == "mysql") {
		res = dbi_conn_queryf(conn_, "SELECT 1 FROM (SELECT COUNT(requests.id) "
		 "AS request_count FROM requests WHERE requests.mode != 3 AND "
		 "requests.client_ip = %s AND requests.profile_id = %i AND requests.date "
		 "> NOW() - INTERVAL (SELECT profiles.flooding_timeframe FROM profiles WHERE "
		 "profiles.id = %i) SECOND) r WHERE r.request_count >= (SELECT "
		 "profiles.flooding_threshold FROM profiles WHERE profiles.id = %i)",
		 client_ip_esc, profile_id, profile_id, profile_id);
	}

	free(client_ip_esc);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute request count query");
	}

	bool status = (dbi_result_get_numrows(res) == 1);

	dbi_result_free(res);

	return status;
}
