<?php
// Test fixture (not a real site): hardened config so security.wp-config reports nothing.
define( 'DB_NAME', 'fixture' );
define( 'DB_HOST', 'localhost' );
define( 'AUTH_KEY', 'fixture-auth-key-not-secret' );
define( 'DISALLOW_FILE_EDIT', true );
define( 'WP_DEBUG', false );
$table_prefix = 'sf_';
