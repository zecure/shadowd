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

#include "whitelist.h"
#include "whitelist_rule.h"
#include "database.h"
#include "log.h"

swd::whitelist::whitelist(const swd::cache_ptr& cache)
 : cache_(cache) {
}

void swd::whitelist::scan(swd::request_ptr& request) {
	swd::parameters parameters = request->get_parameters();

	/* Iterate over all parameters. */
	for (swd::parameters::iterator it_parameter = parameters.begin();
	 it_parameter != parameters.end(); it_parameter++) {
		/* Save the iterators in variables for the sake of readability. */
		swd::parameter_ptr parameter(*it_parameter);

		/* Import the rules from the database. */
		swd::whitelist_rules rules = cache_->get_whitelist_rules(
			request->get_profile()->get_id(),
			request->get_caller(),
			parameter->get_path()
		);

		/**
		 * The parameter needs at least one rule to pass the check. Otherwise
		 * it wouldn't be a whitelist.
		 */
		parameter->set_total_whitelist_rules(rules.size());

		/* Iterate over all rules. */
		for (swd::whitelist_rules::iterator it_rule = rules.begin();
		 it_rule != rules.end(); it_rule++) {
			swd::whitelist_rule_ptr rule(*it_rule);

			try {
				/* Add pointers to all rules that are not adhered to by this parameter. */
				if (!rule->is_adhered_to(parameter->get_value())) {
					parameter->add_whitelist_rule(rule);
				}
			} catch (...) {
				swd::log::i()->send(swd::uncritical_error, "Unexpected whitelist problem");
			}
		}
	}
}
