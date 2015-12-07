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

#ifndef ANALYZER_H
#define ANALYZER_H

#include "request.h"
#include "database.h"
#include "cache.h"

namespace swd {
	/**
	 * @brief Manages the examination of a request.
	 */
	class analyzer {
		public:
			/**
			 * @brief Construct the analyzer.
			 *
			 * @param database The pointer to the database object
			 * @param cache The pointer to the cache object
			 */
			analyzer(const swd::database_ptr& database,
			 const swd::cache_ptr& cache);

			/**
			 * @brief Start the analysis and write results into the request object.
			 *
			 * @param request The pointer to the request object
			 */
			void scan(swd::request_ptr& request);

			/**
			 * @brief Get the flooding status of the request.
			 *
			 * @param request The pointer to the request object
			 * @return The status of the flooding check
			 */
			bool is_flooding(const swd::request_ptr& request) const;

		private:
			/**
			 * @brief The pointer to the database object.
			 */
			swd::database_ptr database_;

			/**
			 * @brief The pointer to the cache object.
			 */
			swd::cache_ptr cache_;
	};

	/**
	 * @brief Analyzer pointer.
	 */
	typedef boost::shared_ptr<swd::analyzer> analyzer_ptr;
}

#endif /* ANALYZER_H */
