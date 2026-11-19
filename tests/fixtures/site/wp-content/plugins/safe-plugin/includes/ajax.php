<?php
/**
 * AJAX handler with nonce and capability checks.
 *
 * @package SafeFixture
 */

defined( 'ABSPATH' ) || exit;

add_action( 'wp_ajax_sf_save', 'sf_ajax_save' );

function sf_ajax_save(): void {
	check_ajax_referer( 'sf_save' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( null, 403 );
	}
	update_option( 'sf_x', sanitize_text_field( wp_unslash( $_POST['x'] ?? '' ) ) );
	wp_send_json_success();
}
