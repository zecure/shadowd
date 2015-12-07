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

#include "blacklist.h"
#include "log.h"

swd::blacklist::blacklist(const swd::cache_ptr& cache)
 : cache_(cache) {
}

void swd::blacklist::scan(swd::request_ptr& request) {
	swd::blacklist_filters filters = cache_->get_blacklist_filters();
	swd::parameters parameters = request->get_parameters();

	/* Iterate over all parameters and check every filter. */
	for (swd::parameters::iterator it_parameter = parameters.begin();
	 it_parameter != parameters.end(); it_parameter++) {
		/* Save the iterators in variables for the sake of readability. */
		swd::parameter_ptr parameter(*it_parameter);

		for (swd::blacklist_filters::iterator it_filter = filters.begin();
		 it_filter != filters.end(); it_filter++) {
			swd::blacklist_filter_ptr filter(*it_filter);

			/* If there is catastrophic backtracking boost throws an exception. */
			try {
				/* Add pointers to all filters that match to the parameter. */
				if (filter->matches(parameter->get_value())) {
					parameter->add_blacklist_filter(filter);
				}
			} catch (...) {
				swd::log::i()->send(swd::uncritical_error, "Unexpected blacklist problem");

				/* Add the filter anyway to avoid a potential blacklist bypass. */
				parameter->add_blacklist_filter(filter);
			}
		}
	}
}
