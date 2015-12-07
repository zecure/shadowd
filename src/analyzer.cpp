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

#include "analyzer.h"
#include "blacklist.h"
#include "whitelist.h"
#include "integrity.h"
#include "blacklist_rule.h"
#include "whitelist_rule.h"
#include "integrity_rule.h"

swd::analyzer::analyzer(swd::database_ptr database, swd::cache_ptr cache) :
 database_(database),
 cache_(cache) {
}

void swd::analyzer::scan(swd::request_ptr request) {
	swd::profile_ptr profile = request->get_profile();

	if (profile->is_blacklist_enabled()) {
		/**
		 * First we initialize the blacklist. This way the filters are only read once per
		 * request and we have a neat cache for the regex objects.
		 */
		swd::blacklist blacklist(cache_);

		/**
		 * The blacklist checks the PHPIDS filters against all parameters and calculates
		 * the total impact for every single parameter. The impacts are saved directly in
		 * the request object.
		 */
		blacklist.scan(request);
	}

	if (profile->is_whitelist_enabled()) {
		swd::whitelist whitelist(cache_);

		/**
		 * The whitelist checks for all parameters if there exists a rule and if it
		 * is adhered to. Every parameter that does not adhere to the conditions gets
		 * tagged in the request object.
		 * At the moment three things get checked: the existence of a rule, the length
		 * of the input and the character set.
		 */
		whitelist.scan(request);
	}

	if (profile->is_integrity_enabled()) {
		swd::integrity integrity(cache_);

		/* Compare the hashes from the database with the hashes in the request. */
		integrity.scan(request);

		/* Check if there is no responsible integrity rule. */
		if (request->get_total_integrity_rules() == 0) {
			request->set_threat(true);
		}

		/* Check if there are integrity rules that are not adhered to. */
		if (request->get_integrity_rules().size() > 0) {
			request->set_threat(true);
		}
	}

	/* Combine the results and determine which parameters are threats. */
	swd::parameters& parameters = request->get_parameters();

	for (swd::parameters::iterator it_parameter = parameters.begin();
	 it_parameter != parameters.end(); it_parameter++) {
		/* Save the iterators in variables for the sake of readability. */
		swd::parameter_ptr parameter(*it_parameter);

		if (profile->is_blacklist_enabled()) {
			int threshold = profile->get_blacklist_threshold();

			swd::blacklist_rules rules = cache_->get_blacklist_rules(
				profile->get_id(),
				request->get_caller(),
				parameter->get_path()
			);

			if (rules.size() > 0) {
				/* Get the most secure threshold in case of an overlap. */
				for (swd::blacklist_rules::iterator it_rule = rules.begin();
				 it_rule != rules.end(); it_rule++) {
					swd::blacklist_rule_ptr rule(*it_rule);

					if (it_rule == rules.begin()) {
						threshold = rule->get_threshold();
					} else if (rule->get_threshold() > -1) {
						if ((threshold < 0) || (rule->get_threshold() < threshold)) {
							threshold = rule->get_threshold();
						}
					}
				}
			}

			/* Check if the impact is higher than the threshold. */
			if ((threshold > -1) && (parameter->get_impact() > threshold)) {
				parameter->set_threat(true);
				parameter->set_critical_blacklist_impact(true);
			}
		}

		if (profile->is_whitelist_enabled()) {
			/* Check if there is no responsible whitelist rule. */
			if (parameter->get_total_whitelist_rules() == 0) {
				parameter->set_threat(true);
			}

			/* Check if there are whitelist rules that are not adhered to. */
			if (parameter->get_whitelist_rules().size() > 0) {
				parameter->set_threat(true);
			}
		}
	}
}

bool swd::analyzer::is_flooding(swd::request_ptr request) {
	return database_->is_flooding(
		request->get_client_ip(),
		request->get_profile()->get_id()
	);
}
