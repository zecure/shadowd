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

swd::storage::storage() :
 stop_(false) {
}

void swd::storage::start() {
	worker_thread_ = boost::thread(
		boost::bind(&swd::storage::process_next, this)
	);
}

void swd::storage::stop() {
	stop_ = true;
}

void swd::storage::add(swd::request_ptr request) {
	/* Mutex to avoid race conditions. */
	boost::unique_lock<boost::mutex> scoped_lock(queue_mutex_);

	/* Add request to end of queue. */
	queue_.push(request);

	/* Notify process_next that there is a new request in the queue. */
	cond_.notify_one();
}

void swd::storage::process_next() {
	boost::unique_lock<boost::mutex> scoped_lock(consumer_mutex_);

	while (!stop_) {
		/* Wait for new request in the queue. */
		cond_.wait(scoped_lock);

		/* Save all queued requests. */
		while (1) {
			queue_mutex_.lock();

			/* This check has to be covered by the mutex. */			
			if (queue_.empty()) {
				break;
			}

			/* Remove oldest request from queue. */
			swd::request_ptr request = queue_.front();
			queue_.pop();

			queue_mutex_.unlock();

			/* Saving is the time-consuming part, do outside of mutex. */
			this->save(request);
		}
	}
}

void swd::storage::save(swd::request_ptr request) {
	int request_id;

	try {
		/* First we save the request and get its id in the database. */
		request_id = swd::database::i()->save_request(
			request->get_profile()->get_id(),
			request->get_caller(),
			(request->get_profile()->is_learning_enabled() ? 1 : 0),
			request->get_client_ip()
		);
	} catch (swd::exceptions::database_exception& e) {
		swd::log::i()->send(swd::uncritical_error, e.what());

		/**
		 * No need to continue if the request couldn't be saved, but no need to
		 * completely block access to the site either.
		 */
		return;
	}

	/* Now iterate over all parameters. */
	swd::parameters& parameters = request->get_parameters();

	for (swd::parameters::iterator it_parameter = parameters.begin();
	 it_parameter != parameters.end(); it_parameter++) {
		swd::parameter_ptr parameter((*it_parameter).second);

		int parameter_id;

		try {
			parameter_id = swd::database::i()->save_parameter(
				request_id,
				(*it_parameter).first,
				parameter->get_value(),
				(request->get_profile()->is_whitelist_enabled() ? parameter->get_total_rules() : -1),
				(parameter->has_critical_impact() ? 1 : 0 ),
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

			swd::database::i()->add_blacklist_parameter_connector(
				blacklist_filter->get_id(),
				parameter_id
			);
		}

		/* Connect the broken whitelist rules with the parameter. */
		swd::whitelist_rules rules = parameter->get_whitelist_rules();

		for (swd::whitelist_rules::iterator it_whitelist_rule = rules.begin();
		 it_whitelist_rule != rules.end(); it_whitelist_rule++) {
			swd::whitelist_rule_ptr whitelist_rule(*it_whitelist_rule);

			swd::database::i()->add_whitelist_parameter_connector(
				whitelist_rule->get_id(),
				parameter_id
			);
		}
	}
}
