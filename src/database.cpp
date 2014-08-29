/**
 * Shadow Daemon -- High-Interaction Web Honeypot
 *
 *   Copyright (C) 2014 Hendrik Buchwald <hb@zecure.org>
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
 */

#include <sstream>
#include <stdio.h>
#include <string.h>
#include <boost/algorithm/string/replace.hpp>

#include "database.h"

void swd::database::connect(std::string driver, std::string host, std::string port,
 std::string username, std::string password, std::string name, std::string encoding) {
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

swd::database_row swd::database::get_profile(std::string server_ip, int profile_id) {
	/**
	 * First we escape server_ip. It comes from a trusted source, but better safe
	 * than sorry. This does not work with std::string though.
	 */
	char *server_ip_esc = strdup(server_ip.c_str());
	dbi_conn_quote_string(conn_, &server_ip_esc);

	/**
	 * Insert the ip and execute the query.
	 *
	 * Multiple sources say that dbi_conn_query_lock is not thread safe. It is not
	 * 100% clear yet if this architecture is affected, but just in case protect it
	 * with a mutex. Stress tests have to be done.
	 */
	pthread_mutex_lock(&dbi_conn_query_lock);
	dbi_result res = dbi_conn_queryf(conn_, "SELECT id, hmac_key, learning, threshold "
	 "FROM profiles WHERE server_ip = %s AND id = %i", server_ip_esc, profile_id);
	pthread_mutex_unlock(&dbi_conn_query_lock);

	/* Don't forget to free server_ip_esc to avoid a memory leak. */
	free(server_ip_esc);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute profile query");
	}

	if (dbi_result_get_numrows(res) != 1) {
		throw swd::exceptions::database_exception("Can't get profile");
	}

	swd::database_row row;

	if (dbi_result_next_row(res)) {
		std::stringstream id;
		id << dbi_result_get_uint(res, "id");
		row["id"] = id.str();

		row["key"] = dbi_result_get_string(res, "hmac_key");

		std::stringstream learning;
		learning << dbi_result_get_uint(res, "learning");
		row["learning"] = learning.str();

		std::stringstream threshold;
		threshold << dbi_result_get_uint(res, "threshold");
		row["threshold"] = threshold.str();
	}

	dbi_result_free(res);

	return row;
}

swd::database_rows swd::database::get_blacklist_filters() {
	pthread_mutex_lock(&dbi_conn_query_lock);
	dbi_result res = dbi_conn_query(conn_, "SELECT id, rule, impact FROM blacklist_filters");
	pthread_mutex_unlock(&dbi_conn_query_lock);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute blacklist_filters query");
	}

	swd::database_rows rows;

	while (dbi_result_next_row(res)) {
		swd::database_row row;

		std::stringstream id;
		id << dbi_result_get_uint(res, "id");
		row["id"] = id.str();

		std::stringstream impact;
		impact << dbi_result_get_uint(res, "impact");
		row["impact"] = impact.str();

		row["rule"] = dbi_result_get_string(res, "rule");

		rows.push_back(row);
	}

	dbi_result_free(res);

	return rows;
}

swd::database_rows swd::database::get_whitelist_rules(int profile,
 std::string caller) {
	char *caller_esc = strdup(caller.c_str());
	dbi_conn_quote_string(conn_, &caller_esc);

	/**
	 * Remove LIKE single character wildcard, because it could result easily in security
	 * problems if a user forgets to escape an underscore. And instead of a percentage sign
	 * it is nicer to use an asterisk, because it is more common.
	 */
	pthread_mutex_lock(&dbi_conn_query_lock);
	dbi_result res = dbi_conn_queryf(conn_, "SELECT r.id, r.path, f.id as filter_id, "
	 "f.rule, f.impact, r.min_length, r.max_length FROM whitelist_rules AS r, "
	 "whitelist_filters AS f WHERE r.filter_id = f.id AND r.profile_id = %i AND %s LIKE "
	 "REPLACE(REPLACE(REPLACE(r.caller, '_', '\\_'), '%', '\\%'), '*', '%') AND "
	 "r.status = %i", profile, caller_esc, STATUS_ACTIVATED);
	pthread_mutex_unlock(&dbi_conn_query_lock);

	free(caller_esc);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute whitelist_rules query");
	}

	swd::database_rows rows;

	while (dbi_result_next_row(res)) {
		swd::database_row row;

		std::stringstream id;
		id << dbi_result_get_uint(res, "id");
		row["id"] = id.str();

		std::stringstream filter_id;
		filter_id << dbi_result_get_uint(res, "filter_id");
		row["filter_id"] = filter_id.str();

		row["rule"] = dbi_result_get_string(res, "rule");

		std::stringstream impact;
		impact << dbi_result_get_uint(res, "impact");
		row["impact"] = impact.str();

		std::stringstream min_length;
		min_length << dbi_result_get_uint(res, "min_length");
		row["min_length"] = min_length.str();

		std::stringstream max_length;
		max_length << dbi_result_get_uint(res, "max_length");
		row["max_length"] = max_length.str();

		row["path"] = dbi_result_get_string(res, "path");

		rows.push_back(row);
	}

	dbi_result_free(res);

	return rows;
}

int swd::database::save_request(int profile, std::string caller, int learning,
 std::string client_ip) {
	char *caller_esc = strdup(caller.c_str());
	dbi_conn_quote_string(conn_, &caller_esc);

	char *client_ip_esc = strdup(client_ip.c_str());
	dbi_conn_quote_string(conn_, &client_ip_esc);

	pthread_mutex_lock(&dbi_conn_query_lock);
	dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO requests (profile_id, "
	 "caller, learning, client_ip) VALUES (%i, %s, %i, %s)", profile, caller_esc,
	 learning, client_ip_esc);

	free(caller_esc);
	free(client_ip_esc);

	if (!res) {
		/**
		 * It is important to unlock the mutex before returning. Otherwise we get
		 * a dead lock and the daemon doesn't work anymore.
		 */
		pthread_mutex_unlock(&dbi_conn_query_lock);
		throw swd::exceptions::database_exception("Can't execute request query");
	}

	int id = dbi_conn_sequence_last(conn_, "requests_id_seq");
	pthread_mutex_unlock(&dbi_conn_query_lock);

	dbi_result_free(res);

	return id;
}

int swd::database::save_parameter(int request, std::string path, std::string value,
 int total_rules, int critical_impact, int threat) {
	char *path_esc = strdup(path.c_str());
	dbi_conn_quote_string(conn_, &path_esc);

	char *value_esc = strdup(value.c_str());
	dbi_conn_quote_string(conn_, &value_esc);

	pthread_mutex_lock(&dbi_conn_query_lock);
	dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO parameters (request_id, "
	 "path, value, total_rules, critical_impact, threat) VALUES (%i, %s, %s, %i, %i, %i)",
	 request, path_esc, value_esc, total_rules, critical_impact, threat);

	free(path_esc);
	free(value_esc);

	if (!res) {
		pthread_mutex_unlock(&dbi_conn_query_lock);
		throw swd::exceptions::database_exception("Can't execute parameter query");
	}

	int id = dbi_conn_sequence_last(conn_, "parameters_id_seq");
	pthread_mutex_unlock(&dbi_conn_query_lock);

	dbi_result_free(res);

	return id;
}

void swd::database::add_blacklist_parameter_connector(int filter, int parameter) {
	pthread_mutex_lock(&dbi_conn_query_lock);
	dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO blacklist_parameters "
	 "(filter_id, parameter_id) VALUES (%i, %i)", filter, parameter);
	pthread_mutex_unlock(&dbi_conn_query_lock);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute blacklist_parameter query");
	}
}

void swd::database::add_whitelist_parameter_connector(int rule, int parameter) {
	pthread_mutex_lock(&dbi_conn_query_lock);
	dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO whitelist_parameters "
	 "(rule_id, parameter_id) VALUES (%i, %i)", rule, parameter);
	pthread_mutex_unlock(&dbi_conn_query_lock);

	if (!res) {
		throw swd::exceptions::database_exception("Can't execute whitelist_parameter query");
	}
}
