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

#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <iostream>
#include <fstream>

#include "daemon.h"
#include "shared.h"

void swd::daemon::set_user(std::string user) {
	struct passwd *u = getpwnam(user.c_str());

	if (!u) {
		throw swd::exceptions::core_exception("getpwnam() failed");
	}

	if (setuid(u->pw_uid) == -1) {
		throw swd::exceptions::core_exception("setuid() failed");
	}
}

void swd::daemon::set_group(std::string group) {
	if (setgroups(0, NULL) == -1) {
		throw swd::exceptions::core_exception("setgroups() failed");
	}

	struct group *g = getgrnam(group.c_str());

	if (!g) {
		throw swd::exceptions::core_exception("getgrnam() failed");
	}

	if (setgid(g->gr_gid) == -1) {
		throw swd::exceptions::core_exception("setgid() failed");
	}
}

void swd::daemon::write_pid(std::string file) {
	std::ofstream out_file(file.c_str());

	if (!out_file.is_open()) {
		throw swd::exceptions::core_exception("Failed to write pid file");
	}

	out_file << getpid();
	out_file.close();
}

void swd::daemon::change_root(std::string directory) {
	if (chroot(directory.c_str()) < 0) {
		throw swd::exceptions::core_exception("chroot() failed");
	}

	if (chdir("/") < 0) {
		throw swd::exceptions::core_exception("chdir() after chroot() failed");
	}
}

void swd::daemon::detach() {
	/**
	 * This forks the process, changes the current working directory to the
	 * root directory and closes the standard input, standard output and
	 * standard error (redirect to /dev/null).
	 */
	if (::daemon(0, 0) < 0) {
		throw swd::exceptions::core_exception("daemon() failed");
	}
}
