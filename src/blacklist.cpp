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

#include <stdlib.h>

#include "blacklist.h"
#include "database.h"
#include "log.h"

swd::blacklist::blacklist(swd::request_ptr request)
 : request_(request) {
}

void swd::blacklist::init() {
	/* Import the filters from the database. */
	swd::database_rows filters = swd::database::i()->get_blacklist_filters();

	/**
	 * Iterate over the filters from the database and save them in blacklist_filter
	 * objects. This increases the performance, because the regex objects are only
	 * created once per request. And it makes the code more readable.
	 */
	for (swd::database_rows::iterator it_filter = filters.begin();
	 it_filter != filters.end(); ++it_filter) {
		swd::blacklist_filter_ptr filter(
			new swd::blacklist_filter(
				atoi((*it_filter)["id"].c_str()),
				(*it_filter)["rule"],
				atoi((*it_filter)["impact"].c_str())
			)
		);

		/* Save the smart pointer of the filter in a vector. */
		filters_.push_back(filter);
	}
}

void swd::blacklist::scan() {
	swd::parameters& parameters = request_->get_parameters();

	/* Iterate over all parameters and check every filter. */
	for (swd::parameters::iterator it_parameter = parameters.begin();
	 it_parameter != parameters.end(); it_parameter++) {
		/* Save the iterators in variables for the sake of readability. */
		swd::parameter_ptr parameter((*it_parameter).second);

		for (swd::blacklist_filters::iterator it_filter = filters_.begin();
		 it_filter != filters_.end(); it_filter++) {
			swd::blacklist_filter_ptr filter(*it_filter);

			/* If there is catastrophic backtracking boost throws an exception. */
			try {
				/* Add pointers to all filters that match to the parameter. */
				if (filter->match(parameter->get_value())) {
					parameter->add_blacklist_filter(filter);
				}
			} catch (...) {}
		}
	}
}
