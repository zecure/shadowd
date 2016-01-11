include(GNUInstallDirs)

install(FILES examples/shadowd.ini
    PERMISSIONS OWNER_WRITE OWNER_READ
    DESTINATION /etc/shadowd)

install(FILES databases/mysql_layout.sql
    databases/pgsql_layout.sql
    databases/updates/pgsql_layout_1.0.0-1.1.0.sql
    databases/updates/mysql_layout_1.0.0-1.1.0.sql
    databases/updates/pgsql_layout_1.1.3-2.0.0.sql
    databases/updates/mysql_layout_1.1.3-2.0.0.sql
    DESTINATION share/shadowd)

install(FILES man/shadowd.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
    COMPONENT doc)
