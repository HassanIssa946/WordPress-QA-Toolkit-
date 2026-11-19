<?php
/**
 * Plugin Name: WPQA stack fixture
 * Description: Stack-mode fixture. MUST be flagged: requires newer PHP/WordPress/WooCommerce than installed,
 *              composer/npm constraints that exclude the installed versions, client IP from a spoofable header.
 * Version: 0.1.0
 * Requires PHP: 8.4
 * Requires at least: 7.2
 * WC requires at least: 9.0
 * Text Domain: stack-plugin
 * Update URI: false
 */

defined( 'ABSPATH' ) || exit;

require __DIR__ . '/includes/limits.php';
