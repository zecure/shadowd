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
 */

#include <iostream>
#include <fstream>

#include "config.h"
#include "build_config.h"

swd::config::config() :
 od_generic_("Generic options"),
 od_server_("Server options"),
 od_daemon_("Daemon options"),
 od_database_("Database options") {
	od_generic_.add_options()
		("help,h", "produce help message")
		("version,v", "print version string")
		("config,c", po::value<std::string>(), "configuration file")
		("verbose,V", "show more debug output");

	od_server_.add_options()
		("address,a", po::value<std::string>()->default_value("127.0.0.1"), "bind to ip address")
		("port,p", po::value<std::string>()->default_value("9115"), "bind to port")
		("ssl,S", "activate ssl")
		("ssl-cert,C", po::value<std::string>(), "path to ssl cert")
		("ssl-key,K", po::value<std::string>(), "path to ssl key")
		("ssl-dh,H", po::value<std::string>(), "path to dhparam file")
		("threads,t", po::value<int>()->default_value(10), "sets the size of the threadpool");

	od_daemon_.add_options()
		("daemonize,D", "detach and become a daemon")
		("log,L", po::value<std::string>(), "file to store logs")
		("pid,P", po::value<std::string>(), "pid file")
		("user,U", po::value<std::string>(), "user to run daemon as")
		("group,G", po::value<std::string>(), "group to run daemon as")
		("chroot,R", po::value<std::string>(), "change root directory");

	od_database_.add_options()
		("db-driver", po::value<std::string>()->default_value("pgsql"))
		("db-host", po::value<std::string>()->default_value("127.0.0.1"))
		("db-port", po::value<std::string>()->default_value("5432"))
		("db-name", po::value<std::string>()->default_value("shadowd"))
		("db-user", po::value<std::string>()->default_value("shadowd"))
		("db-password", po::value<std::string>()->default_value(""))
		("db-encoding", po::value<std::string>()->default_value("UTF-8"));
}

void swd::config::parse_command_line(int argc, char** argv) {
	po::options_description combination;
	combination.add(od_generic_).add(od_server_).add(od_daemon_);

	try {
		po::store(po::command_line_parser(argc, argv).options(combination).run(), vm_);
		po::notify(vm_);
	} catch (boost::program_options::unknown_option& e) {
		throw swd::exceptions::config_exception(e.what());
	}

	if (this->defined("version")) {
		std::cout << "shadowd " << SHADOWD_VERSION << std::endl;
		exit(0);
	}

	if (this->defined("help")) {
		std::cout << "Shadow Daemon " << SHADOWD_VERSION << " -- Web Application Firewall"
				  << std::endl << combination << std::endl;
		exit(0);
	}
}

void swd::config::parse_config_file(std::string file) {
	std::ifstream ifs(file.c_str());

	if (!ifs) {
		throw swd::exceptions::core_exception("Can't open config file");
	}

	po::options_description combination;
	combination.add(od_server_).add(od_daemon_).add(od_database_);

	try {
		po::store(po::parse_config_file(ifs, combination, true), vm_);
		po::notify(vm_);
	} catch (boost::program_options::unknown_option& e) {
		throw swd::exceptions::config_exception(e.what());
	} catch (...) {
		throw swd::exceptions::config_exception("invalid configuration file");
	}

	ifs.close();
}

void swd::config::validate() {
	if (!this->defined("threads") || (this->get<int>("threads") < 1)) {
		throw swd::exceptions::config_exception("threadpool must be greater than zero");
	}

	if (this->defined("daemonize")) {
		if (!this->defined("pid")) {
			throw swd::exceptions::config_exception("daemonize requires a pid file");
		}
	}

	if (!this->defined("address") || !this->defined("port")) {
		throw swd::exceptions::config_exception("address and port required");
	}

	if (this->defined("ssl")) {
		if (!this->defined("ssl-cert") || !this->defined("ssl-key") || !this->defined("ssl-dh")) {
			throw swd::exceptions::config_exception("required ssl input missing");
		}
	}

	if (!this->defined("config")) {
		throw swd::exceptions::config_exception("config required");
	}
}
