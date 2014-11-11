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

#include <iostream>

#include "storage.h"
#include "database.h"
#include "log.h"

void swd::storage::save(swd::request_ptr request) {
	/**
	 * Nothing to do if there are no threats and learning is disabled. If there
	 * is at least one threat the complete request gets recorded.
	 */
	if (!request->has_threats() && !request->get_profile()->is_learning()) {
		return;
	}

	int request_id;

	try {
		/* First we save the request and get its id in the database. */
		request_id = swd::database::i()->save_request(
			request->get_profile()->get_id(),
			request->get_caller(),
			(request->get_profile()->is_learning() ? 1 : 0),
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
				parameter->get_total_rules(),
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
