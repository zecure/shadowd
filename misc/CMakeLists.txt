include(GNUInstallDirs)

install(FILES examples/shadowd.ini
	PERMISSIONS OWNER_WRITE OWNER_READ
	DESTINATION /etc/shadowd)

install(FILES databases/mysql_layout.sql
	databases/pgsql_layout.sql
	DESTINATION share/shadowd)

install(FILES man/shadowd.1
	DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
	COMPONENT doc)
