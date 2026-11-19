<?php
/**
 * Inline closure callback on an always-true REST write route that checks nothing → wp.rest.public-write.
 */

add_action(
	'rest_api_init',
	static function () {
		register_rest_route(
			'vf/v1',
			'/closure-write',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'permission_callback' => '__return_true',
				'callback'            => static function ( WP_REST_Request $req ) {
					update_option( 'vf_closure', sanitize_text_field( (string) $req['v'] ) );
					return rest_ensure_response( array( 'ok' => true ) );
				},
			)
		);
	}
);
