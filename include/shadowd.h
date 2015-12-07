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

#ifndef SHADOWD_H
#define SHADOWD_H

#include "daemon.h"
#include "server.h"
#include "database.h"
#include "cache.h"
#include "analyzer.h"
#include "storage.h"

namespace swd {
	/**
	 * @brief Glues everything together.
	 */
	class shadowd {
		public:
			/**
			 * @brief Construct a shadowd object.
			 */
			shadowd();

			/**
			 * @brief Prepare the configuration, daemonization and the
			 *  initialization of the server.
			 *
			 * @param argc The number of command line arguments
			 * @param argv The command line arguments
			 */
			void init(int argc, char** argv);

			/**
			 * @brief Tell the server to add threads to the thread pool.
			 */
			void start();

		private:
			swd::database_ptr database_;
			swd::cache_ptr cache_;
			swd::analyzer_ptr analyzer_;
			swd::storage_ptr storage_;
			swd::daemon daemon_;
			swd::server server_;
	};
}

#endif /* SHADOWD_H */

/**
 * @mainpage Disk and Execution Monitor
 *
 * This reference is intended for developers only. If you just want to use the
 * Shadow Daemon system go to the <a href="https://shadowd.zecure.org/">user 
 * documentation</a> instead.
 *
 * @author Hendrik Buchwald
 */
