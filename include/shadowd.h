/**
 * Shadow Daemon -- Web Application Firewall
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

#ifndef SHADOWD_H
#define SHADOWD_H

#include "daemon.h"
#include "server.h"

namespace swd {
	/**
	 * @brief Glues everything together.
	 */
	class shadowd {
		public:
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
			swd::daemon daemon_;
			swd::server server_;
	};
}

#endif /* SHADOWD_H */

/**
 * @mainpage Disk and Execution Monitor
 *
 * This reference is intended for developers only. If you just want to use the
 * Shadow Daemon system go to the <a href="https://shadowd.zecure.org/docs/current/">
 * user documentation</a> instead.
 *
 * <img src="uml.svg" alt="shadowd uml diagram" style="width: 100%" />
 * <a href="uml.svg" style="float: right">Full size</a>
 *
 * @author Hendrik Buchwald
 */
