<?php
// Fixture: two client-IP patterns the stack mode must report.
defined( 'ABSPATH' ) || exit;

/** Rate limit keyed on REMOTE_ADDR (fine without a proxy; risky behind a CDN). */
function stf_limit_contact(): bool {
	$ip   = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	$key  = 'stf_rl_' . md5( $ip );
	$hits = (int) get_transient( $key );
	if ( $hits >= 5 ) {
		return false; // too many attempts
	}
	set_transient( $key, $hits + 1, 10 * MINUTE_IN_SECONDS );
	return true;
}

/** Login throttle that trusts X-Forwarded-For as sent by the client. */
function stf_login_throttle(): bool {
	$ip   = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '';
	$hits = (int) get_transient( 'stf_login_' . md5( $ip ) );
	set_transient( 'stf_login_' . md5( $ip ), $hits + 1, HOUR_IN_SECONDS );
	return $hits < 10;
}
