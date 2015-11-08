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

#include "integrity.h"
#include "integrity_rule.h"
#include "hash.h"
#include "database.h"
#include "log.h"

swd::integrity::integrity(swd::request_ptr request)
 : request_(request) {
}

void swd::integrity::scan() {
	/* Import the rules from the database. */
	swd::integrity_rules rules = swd::database::i()->get_integrity_rules(
		request_->get_profile()->get_id(),
		request_->get_caller()
	);

	/**
	 * The request needs at least one rule to pass the check. Otherwise
	 * it wouldn't be a whitelist.
	 */
	request_->set_total_integrity_rules(rules.size());

	/* Iterate over all rules. */
	for (swd::integrity_rules::iterator it_rule = rules.begin();
	 it_rule != rules.end(); it_rule++) {
		swd::integrity_rule_ptr rule(*it_rule);

		try {
			swd::hash_ptr hash = request_->get_hash(rule->get_algorithm());

			/* Add pointers to all rules that do not match. */
			if (!hash || (rule->get_digest() != hash->get_digest())) {
				request_->add_integrity_rule(rule);
			}
		} catch (...) {
			swd::log::i()->send(swd::uncritical_error, "Unexpected integrity problem");
		}
	}
}
