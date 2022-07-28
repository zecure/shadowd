/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2022 Hendrik Buchwald <hb@zecure.org>
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
#include <thread>
#include <chrono>

#include "database.h"
#include "log.h"
#include "core_exception.h"
#include "database_exception.h"

void swd::database::connect(const std::string& driver, const std::string& host,
 const std::string& port, const std::string& username, const std::string& password,
 const std::string& name, const std::string& encoding, bool wait) {
#if defined(HAVE_DBI_NEW)
    dbi_initialize_r(nullptr, &instance_);
    conn_ = dbi_conn_new_r(driver.c_str(), instance_);
#else
    dbi_initialize(nullptr);
    conn_ = dbi_conn_new(driver.c_str());
#endif

    dbi_conn_set_option(conn_, "host", host.c_str());
    dbi_conn_set_option(conn_, "port", port.c_str());
    dbi_conn_set_option(conn_, "username", username.c_str());
    dbi_conn_set_option(conn_, "password", password.c_str());
    dbi_conn_set_option(conn_, "dbname", name.c_str());
    dbi_conn_set_option(conn_, "encoding", encoding.c_str());

    bool retry = true;
    int attempt = 0;
    do {
        if (dbi_conn_connect(conn_) < 0) {
            if (!wait) {
                throw swd::exceptions::core_exception("Can't connect to database server");
            }

            attempt++;
            int sleep_time = attempt + 2;
            swd::log::i()->send(
                swd::uncritical_error,
                "Can't connect to database server, retrying in " + std::to_string(sleep_time) + " seconds"
            );
            std::this_thread::sleep_for(std::chrono::seconds(sleep_time));
        } else {
            retry = false;
        }
    } while (retry);
}

void swd::database::disconnect() {
    dbi_conn_close(conn_);
#if defined(HAVE_DBI_NEW)
    dbi_shutdown_r(instance_);
#endif
}

void swd::database::ensure_connection() {
    boost::unique_lock scoped_lock(dbi_mutex_);

    if (dbi_conn_ping(conn_) < 1) {
        swd::log::i()->send(swd::notice, "Dropped database connection");

        if (dbi_conn_connect(conn_) < 0) {
            throw swd::exceptions::database_exception("Lost database connection");
        }
    }
}

swd::profile_ptr swd::database::get_profile(const std::string& server_ip,
 const unsigned long long& profile_id) {
    std::stringstream log_message;
    log_message << "Get profile from db -> server_ip: " << server_ip
     << "; profile_id: " << profile_id;

    swd::log::i()->send(swd::notice, log_message.str());

    /* Test the database connection status. Tries to reconnect if disconnected. */
    ensure_connection();

    /* Mutex to avoid race conditions. */
    boost::unique_lock scoped_lock(dbi_mutex_);

    /**
     * First we escape server_ip. It comes from a trusted source, but better safe
     * than sorry. This does not work with std::string though.
     */
    char *server_ip_esc = strdup(server_ip.c_str());
    dbi_conn_quote_string(conn_, &server_ip_esc);

    /* Insert the ip and execute the query. */
    dbi_result res = dbi_conn_queryf(conn_, "SELECT id, hmac_key, mode, "
     "whitelist_enabled, blacklist_enabled, integrity_enabled, flooding_enabled, "
     "blacklist_threshold, cache_outdated FROM profiles WHERE %s LIKE "
     "prepare_wildcard(server_ip) AND id = %llu", server_ip_esc, profile_id);

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

    swd::profile_ptr profile(new swd::profile());
    profile->set_server_ip(server_ip),
    profile->set_id(dbi_result_get_ulonglong(res, "id"));
    profile->set_mode(dbi_result_get_uint(res, "mode"));
    profile->set_whitelist_enabled(dbi_result_get_uint(res, "whitelist_enabled") == 1);
    profile->set_blacklist_enabled(dbi_result_get_uint(res, "blacklist_enabled") == 1);
    profile->set_integrity_enabled(dbi_result_get_uint(res, "integrity_enabled") == 1);
    profile->set_flooding_enabled(dbi_result_get_uint(res, "flooding_enabled") == 1);
    profile->set_key(dbi_result_get_string(res, "hmac_key"));
    profile->set_blacklist_threshold(dbi_result_get_int(res, "blacklist_threshold"));
    profile->set_cache_outdated(dbi_result_get_uint(res, "cache_outdated") == 1);

    dbi_result_free(res);

    return profile;
}

swd::blacklist_rules swd::database::get_blacklist_rules(const unsigned long long& profile_id,
 const std::string& caller, const std::string& path) {
    swd::log::i()->send(swd::notice, "Get blacklist rules from db");

    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    char *caller_esc = strdup(caller.c_str());
    dbi_conn_quote_string(conn_, &caller_esc);

    char *path_esc = strdup(path.c_str());
    dbi_conn_quote_string(conn_, &path_esc);

    dbi_result res = dbi_conn_queryf(conn_, "SELECT r.id, r.path, r.threshold "
     "FROM blacklist_rules AS r WHERE r.profile_id = %llu AND %s LIKE "
     "prepare_wildcard(r.caller) AND %s LIKE prepare_wildcard(r.path) AND "
     "r.status = %i", profile_id, caller_esc, path_esc, STATUS_ACTIVATED);

    free(caller_esc);
    free(path_esc);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute blacklist_rules query");
    }

    swd::blacklist_rules rules;

    while (dbi_result_next_row(res)) {
        swd::blacklist_rule_ptr rule(new swd::blacklist_rule());
        rule->set_id(dbi_result_get_ulonglong(res, "id"));
        rule->set_threshold(dbi_result_get_int(res, "threshold"));

        rules.push_back(rule);
    }

    dbi_result_free(res);

    return rules;
}

swd::blacklist_filters swd::database::get_blacklist_filters() {
    swd::log::i()->send(swd::notice, "Get blacklist filters from db");

    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    dbi_result res = dbi_conn_query(conn_, "SELECT id, impact, rule FROM blacklist_filters");

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute blacklist_filters query");
    }

    swd::blacklist_filters filters;

    while (dbi_result_next_row(res)) {
        swd::blacklist_filter_ptr filter(new swd::blacklist_filter());
        filter->set_id(dbi_result_get_ulonglong(res, "id"));
        filter->set_impact(dbi_result_get_uint(res, "impact"));
        filter->set_regex(dbi_result_get_string(res, "rule"));

        filters.push_back(filter);
    }

    dbi_result_free(res);

    return filters;
}

swd::whitelist_rules swd::database::get_whitelist_rules(const unsigned long long& profile_id,
 const std::string& caller, const std::string& path) {
    swd::log::i()->send(swd::notice, "Get whitelist rules from db");

    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

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
     "whitelist_filters AS f WHERE r.filter_id = f.id AND r.profile_id = %llu AND %s LIKE "
     "prepare_wildcard(r.caller) AND %s LIKE prepare_wildcard(r.path) AND r.status = %i",
     profile_id, caller_esc, path_esc, STATUS_ACTIVATED);

    free(caller_esc);
    free(path_esc);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute whitelist_rules query");
    }

    swd::whitelist_rules rules;

    while (dbi_result_next_row(res)) {
        swd::whitelist_filter_ptr filter(new swd::whitelist_filter());
        filter->set_id(dbi_result_get_ulonglong(res, "filter_id"));
        filter->set_regex(dbi_result_get_string(res, "rule"));

        swd::whitelist_rule_ptr rule(new swd::whitelist_rule());
        rule->set_id(dbi_result_get_ulonglong(res, "id"));
        rule->set_filter(filter);
        rule->set_min_length(dbi_result_get_int(res, "min_length"));
        rule->set_max_length(dbi_result_get_int(res, "max_length"));

        rules.push_back(rule);
    }

    dbi_result_free(res);

    return rules;
}

swd::integrity_rules swd::database::get_integrity_rules(const unsigned long long& profile_id,
 const std::string& caller) {
    swd::log::i()->send(swd::notice, "Get integrity rules from db");

    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    char *caller_esc = strdup(caller.c_str());
    dbi_conn_quote_string(conn_, &caller_esc);

    dbi_result res = dbi_conn_queryf(conn_, "SELECT r.id, r.algorithm, r.digest FROM "
     "integrity_rules AS r WHERE r.profile_id = %llu AND %s LIKE prepare_wildcard(r.caller) "
     "AND r.status = %i", profile_id, caller_esc, STATUS_ACTIVATED);

    free(caller_esc);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute whitelist_rules query");
    }

    swd::integrity_rules rules;

    while (dbi_result_next_row(res)) {
        swd::integrity_rule_ptr rule(new swd::integrity_rule());
        rule->set_id(dbi_result_get_ulonglong(res, "id"));
        rule->set_algorithm(dbi_result_get_string(res, "algorithm"));
        rule->set_digest(dbi_result_get_string(res, "digest"));

        rules.push_back(rule);
    }

    dbi_result_free(res);

    return rules;
}

unsigned long long swd::database::save_request(const unsigned long long& profile_id, const std::string& caller,
 const std::string& resource, const unsigned int& mode, const std::string& client_ip,
 const int& total_integrity_rules) {
    std::stringstream log_message;
    log_message << "Save request -> profile: " << profile_id
     << "; caller: " << caller << "; resource: " << resource
     << "; mode: " << mode << "; client_ip: " << client_ip;

    swd::log::i()->send(swd::notice, log_message.str());

    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    char *caller_esc = strdup(remove_null(caller).c_str());
    dbi_conn_quote_string(conn_, &caller_esc);

    char *resource_esc = strdup(remove_null(resource).c_str());
    dbi_conn_quote_string(conn_, &resource_esc);

    char *client_ip_esc = strdup(remove_null(client_ip).c_str());
    dbi_conn_quote_string(conn_, &client_ip_esc);

    dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO requests (profile_id, "
     "caller, resource, mode, client_ip, total_integrity_rules) VALUES (%llu, %s, "
     "%s, %i, %s, %i)", profile_id, caller_esc, resource_esc, mode, client_ip_esc,
     total_integrity_rules);

    free(caller_esc);
    free(resource_esc);
    free(client_ip_esc);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute request query");
    }

    unsigned long long id = dbi_conn_sequence_last(conn_, "requests_id_seq");

    dbi_result_free(res);

    return id;
}

unsigned long long swd::database::save_parameter(const unsigned long long& request_id, const std::string& path,
 const std::string& value, const int& total_whitelist_rules,
 const int& critical_impact, const int& threat) {
    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    char *path_esc = strdup(remove_null(path).c_str());
    dbi_conn_quote_string(conn_, &path_esc);

    char *value_esc = strdup(remove_null(value).c_str());
    dbi_conn_quote_string(conn_, &value_esc);

    dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO parameters "
     "(request_id, path, value, total_whitelist_rules, critical_impact, threat) "
     "VALUES (%llu, %s, %s, %i, %i, %i)", request_id, path_esc, value_esc,
     total_whitelist_rules, critical_impact, threat);

    free(path_esc);
    free(value_esc);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute parameter query");
    }

    unsigned long long id = dbi_conn_sequence_last(conn_, "parameters_id_seq");

    dbi_result_free(res);

    return id;
}


unsigned long long swd::database::save_hash(const unsigned long long& request_id, const std::string& algorithm,
 const std::string& digest) {
    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    char *algorithm_esc = strdup(remove_null(algorithm).c_str());
    dbi_conn_quote_string(conn_, &algorithm_esc);

    char *digest_esc = strdup(remove_null(digest).c_str());
    dbi_conn_quote_string(conn_, &digest_esc);

    dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO hashes (request_id, "
     "algorithm, digest) VALUES (%llu, %s, %s)", request_id, algorithm_esc, digest_esc);

    free(algorithm_esc);
    free(digest_esc);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute hash query");
    }

    unsigned long long id = dbi_conn_sequence_last(conn_, "hashes_id_seq");

    dbi_result_free(res);

    return id;
}

void swd::database::add_blacklist_parameter_connector(const unsigned long long& filter_id,
 const unsigned long long& parameter_id) {
    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO blacklist_parameters "
     "(filter_id, parameter_id) VALUES (%llu, %llu)", filter_id, parameter_id);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute blacklist_parameter query");
    }

    dbi_result_free(res);
}

void swd::database::add_whitelist_parameter_connector(const unsigned long long& rule_id,
 const unsigned long long& parameter_id) {
    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO whitelist_parameters "
     "(rule_id, parameter_id) VALUES (%llu, %llu)", rule_id, parameter_id);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute whitelist_parameter query");
    }

    dbi_result_free(res);
}

void swd::database::add_integrity_request_connector(const unsigned long long& rule_id,
 const unsigned long long& request_id) {
    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    dbi_result res = dbi_conn_queryf(conn_, "INSERT INTO integrity_requests "
     "(rule_id, request_id) VALUES (%llu, %llu)", rule_id, request_id);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute integrity_request query");
    }

    dbi_result_free(res);
}

bool swd::database::is_flooding(const std::string& client_ip,
 const unsigned long long& profile_id) {
    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    char *client_ip_esc = strdup(client_ip.c_str());
    dbi_conn_quote_string(conn_, &client_ip_esc);

    dbi_result res = dbi_conn_queryf(conn_, "SELECT is_flooding(%llu, %s) AS result",
     profile_id, client_ip_esc);

    free(client_ip_esc);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute request count query");
    }

    bool flooding = false;

    if (dbi_result_get_numrows(res) == 1) {
        if (!dbi_result_next_row(res)) {
            throw swd::exceptions::database_exception("No flooding?");
        }

        flooding = (dbi_result_get_uint(res, "result") == 1);
    }

    dbi_result_free(res);

    return flooding;
}

void swd::database::set_cache_outdated(const bool& cache_outdated) {
    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    dbi_result res = dbi_conn_queryf(conn_, "UPDATE profiles SET cache_outdated = %i ",
     (cache_outdated ? 1 : 0));

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute cache_outdated query");
    }

    dbi_result_free(res);
}

void swd::database::set_cache_outdated(const unsigned long long& profile_id,
 const bool& cache_outdated) {
    ensure_connection();

    boost::unique_lock scoped_lock(dbi_mutex_);

    dbi_result res = dbi_conn_queryf(conn_, "UPDATE profiles SET cache_outdated = %i "
     "WHERE id = %llu", (cache_outdated ? 1 : 0), profile_id);

    if (!res) {
        throw swd::exceptions::database_exception("Can't execute cache_outdated query");
    }

    dbi_result_free(res);
}

std::string swd::database::remove_null(std::string target) {
    std::replace(target.begin(), target.end(), '\0', ' ');
    return target;
}
