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

#include <iostream>

#include "storage.h"
#include "database.h"
#include "log.h"

swd::storage::storage(const swd::database_ptr& database) :
 database_(database),
 stop_(false) {
}

void swd::storage::start() {
	worker_thread_ = boost::thread(
		boost::bind(&swd::storage::process_next, this)
	);
}

void swd::storage::stop() {
	/* Stop on next loop. */
	stop_ = true;

	/* Wake up and join thread to finish current loop. */
	cond_.notify_one();
	worker_thread_.join();
}

void swd::storage::add(const swd::request_ptr& request) {
	/* Mutex to avoid race conditions. */
	boost::unique_lock<boost::mutex> scoped_lock(queue_mutex_);

	/* Add request to end of queue. */
	queue_.push(request);

	/* Notify process_next that there is a new request in the queue. */
	cond_.notify_one();
}

void swd::storage::process_next() {
	boost::unique_lock<boost::mutex> consumer_lock(consumer_mutex_);

	while (!stop_) {
		/* Wait for a new request in the queue. */
		while (1) {
			/* Do not wait if there are still elements in the queue. */
			{
				boost::unique_lock<boost::mutex> queue_lock(queue_mutex_);

				if (!queue_.empty()) {
					break;
				}
			}

			/* If stop is activated do not go to sleep again. */
			if (stop_) {
				return;
			}

			cond_.wait(consumer_lock);
		}

		/* Move oldest element of queue to request. */
		swd::request_ptr request;

		{
			boost::unique_lock<boost::mutex> queue_lock(queue_mutex_);

			request = queue_.front();
			queue_.pop();
		}

		/* Saving is the time-consuming part, do outside of mutex. */
		this->save(request);
	}
}

void swd::storage::save(const swd::request_ptr& request) {
	int request_id;

	try {
		/* First we save the request and get its id in the database. */
		request_id = database_->save_request(
			request->get_profile()->get_id(),
			request->get_caller(),
			request->get_resource(),
			request->get_profile()->get_mode(),
			request->get_client_ip(),
			(request->get_profile()->is_integrity_enabled() ? request->get_total_integrity_rules() : -1)
		);
	} catch (swd::exceptions::database_exception& e) {
		swd::log::i()->send(swd::uncritical_error, e.what());

		/**
		 * No need to continue if the request couldn't be saved, but no need to
		 * completely block access to the site either.
		 */
		return;
	}

	/* Save all hashes of the request. */
	swd::hashes hashes = request->get_hashes();

	for (swd::hashes::iterator it_hash = hashes.begin(); it_hash != hashes.end(); it_hash++) {
		swd::hash_ptr hash((*it_hash).second);

		try {
			database_->save_hash(
				request_id,
				hash->get_algorithm(),
				hash->get_digest()
			);
		} catch (swd::exceptions::database_exception& e) {
			swd::log::i()->send(swd::uncritical_error, e.what());
			continue;
		}
	}

	/* Connect the broken integrity rules with the request. */
	swd::integrity_rules integrity_rules = request->get_integrity_rules();

	for (swd::integrity_rules::iterator it_integrity_rule = integrity_rules.begin();
	 it_integrity_rule != integrity_rules.end(); it_integrity_rule++) {
		swd::integrity_rule_ptr integrity_rule(*it_integrity_rule);

		try {
			database_->add_integrity_request_connector(
				integrity_rule->get_id(),
				request_id
			);
		} catch (swd::exceptions::database_exception& e) {
			swd::log::i()->send(swd::uncritical_error, e.what());
			continue;
		}
	}

	/* Now iterate over all parameters. */
	swd::parameters parameters = request->get_parameters();

	for (swd::parameters::iterator it_parameter = parameters.begin();
	 it_parameter != parameters.end(); it_parameter++) {
		swd::parameter_ptr parameter(*it_parameter);

		int parameter_id;

		try {
			parameter_id = database_->save_parameter(
				request_id,
				parameter->get_path(),
				parameter->get_value(),
				(request->get_profile()->is_whitelist_enabled() ? parameter->get_total_whitelist_rules() : -1),
				(parameter->has_critical_blacklist_impact() ? 1 : 0 ),
				(parameter->is_threat() ? 1 : 0 )
			);
		} catch (swd::exceptions::database_exception& e) {
			swd::log::i()->send(swd::uncritical_error, e.what());
			continue;
		}

		/* Connect the matching blacklist filters with the parameter. */
		swd::blacklist_filters blacklist_filters = parameter->get_blacklist_filters();

		for (swd::blacklist_filters::iterator it_blacklist_filter = blacklist_filters.begin();
		 it_blacklist_filter != blacklist_filters.end(); it_blacklist_filter++) {
			swd::blacklist_filter_ptr blacklist_filter(*it_blacklist_filter);

			try {
				database_->add_blacklist_parameter_connector(
					blacklist_filter->get_id(),
					parameter_id
				);
			} catch (swd::exceptions::database_exception& e) {
				swd::log::i()->send(swd::uncritical_error, e.what());
				continue;
			}
		}

		/* Connect the broken whitelist rules with the parameter. */
		swd::whitelist_rules whitelist_rules = parameter->get_whitelist_rules();

		for (swd::whitelist_rules::iterator it_whitelist_rule = whitelist_rules.begin();
		 it_whitelist_rule != whitelist_rules.end(); it_whitelist_rule++) {
			swd::whitelist_rule_ptr whitelist_rule(*it_whitelist_rule);

			try {
				database_->add_whitelist_parameter_connector(
					whitelist_rule->get_id(),
					parameter_id
				);
			} catch (swd::exceptions::database_exception& e) {
				swd::log::i()->send(swd::uncritical_error, e.what());
				continue;
			}
		}
	}
}
