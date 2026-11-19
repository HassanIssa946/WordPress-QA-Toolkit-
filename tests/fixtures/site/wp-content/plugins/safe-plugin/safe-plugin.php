<?php
/**
 * Plugin Name: WPQA safe fixture
 * Description: Secure patterns (several taken from a real site that produced false positives). MUST produce zero security findings.
 * Version: 1.0.0
 * Requires PHP: 8.1
 * Text Domain: safe-plugin
 * Update URI: false
 */

defined( 'ABSPATH' ) || exit;

define( 'SF_DIR', plugin_dir_path( __FILE__ ) );

require SF_DIR . 'includes/rest.php';
require SF_DIR . 'includes/settings.php';
require SF_DIR . 'includes/ajax.php';

/** Real-site pattern: only the WordPress table name is interpolated ({$wpdb->postmeta}). */
function sf_media_map(): array {
	global $wpdb;
	$rows = $wpdb->get_results( "SELECT post_id, meta_value FROM {$wpdb->postmeta} WHERE meta_key = '_sf_source'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$map  = array();
	foreach ( (array) $rows as $r ) {
		$map[ $r->meta_value ] = (int) $r->post_id;
	}
	return $map;
}

/** Table prefix concatenation is not user input either. */
function sf_log_count(): int {
	global $wpdb;
	return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $wpdb->prefix . 'sf_log' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
}

/** Variables go through prepare(). */
function sf_post_row( int $id ) {
	global $wpdb;
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
}

/** Escaped request output. */
function sf_search_echo(): void {
	echo esc_html( sanitize_text_field( wp_unslash( $_GET['q'] ?? '' ) ) ); // phpcs:ignore WordPress.Security.NonceVerification
}

/** Safe redirect. */
function sf_go_home(): void {
	wp_safe_redirect( home_url( '/' ) );
	exit;
}
