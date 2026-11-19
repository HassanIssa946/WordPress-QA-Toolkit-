<?php
/**
 * Real-site pattern: a public contact form REST route. permission_callback is __return_true on purpose,
 * the callback verifies a nonce (plus honeypot and rate limit). Also a nonce-checked inline closure and a
 * public read-only route.
 *
 * @package SafeFixture
 */

defined( 'ABSPATH' ) || exit;

add_action(
	'rest_api_init',
	static function () {
		register_rest_route(
			'sf/v1',
			'/contact',
			array(
				'methods'             => 'POST',
				'callback'            => 'sf_rest_contact',
				'permission_callback' => '__return_true', // Public form; protected by nonce, honeypot and rate limit below.
				'args'                => array(
					'message' => array( 'type' => 'string', 'required' => true, 'sanitize_callback' => 'sanitize_textarea_field' ),
					'website' => array( 'type' => 'string', 'default' => '' ), // Honeypot.
					'nonce'   => array( 'type' => 'string', 'required' => true ),
				),
			)
		);

		register_rest_route(
			'sf/v1',
			'/vote',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'permission_callback' => '__return_true',
				'callback'            => static function ( WP_REST_Request $req ) {
					if ( ! wp_verify_nonce( (string) $req['nonce'], 'sf_vote' ) ) {
						return new WP_Error( 'sf_nonce', 'Expired', array( 'status' => 403 ) );
					}
					update_option( 'sf_votes', (int) get_option( 'sf_votes' ) + 1 );
					return rest_ensure_response( array( 'ok' => true ) );
				},
			)
		);

		register_rest_route(
			'sf/v1',
			'/items',
			array(
				'methods'             => 'GET',
				'callback'            => 'sf_rest_items',
				'permission_callback' => '__return_true', // Published, public data.
			)
		);
	}
);

function sf_rest_contact( WP_REST_Request $req ) {
	if ( ! wp_verify_nonce( (string) $req['nonce'], 'sf_contact' ) ) {
		return new WP_Error( 'sf_nonce', 'Your session expired.', array( 'status' => 403 ) );
	}
	if ( '' !== trim( (string) $req['website'] ) ) {
		return rest_ensure_response( array( 'ok' => true ) );
	}
	$ip   = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	$key  = 'sf_rl_' . md5( $ip );
	$hits = (int) get_transient( $key );
	if ( $hits >= 5 ) {
		return new WP_Error( 'sf_rate', 'Too many messages.', array( 'status' => 429 ) );
	}
	set_transient( $key, $hits + 1, 10 * MINUTE_IN_SECONDS );
	wp_mail( get_option( 'admin_email' ), 'Contact', (string) $req['message'] );
	return rest_ensure_response( array( 'ok' => true ) );
}

function sf_rest_items() {
	return rest_ensure_response( get_posts( array( 'post_status' => 'publish', 'fields' => 'ids' ) ) );
}
