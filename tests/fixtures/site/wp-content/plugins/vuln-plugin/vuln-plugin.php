<?php
/**
 * Plugin Name: WPQA vulnerable fixture
 * Description: Deliberately insecure code. Every pattern below MUST be detected by the scanner. Never deploy.
 * Version: 1.0.0
 */

// No ABSPATH guard on purpose (wp.direct-access).
add_action( 'init', 'vf_init' );

// wp.xss.echo-request
function vf_echo() {
	echo $_GET['q'];
}

// wp.sqli.unprepared (critical: request data in the query, table name interpolation must not hide it)
function vf_sqli_request() {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_title = '" . $_GET['t'] . "'" );
}

// wp.sqli.unprepared (high: variable concatenated into SQL)
function vf_sqli_variable( $id ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM {$wpdb->posts} WHERE ID = $id" );
}

add_action(
	'rest_api_init',
	function () {
		// wp.rest.no-permission-callback (critical: write route without permission_callback)
		register_rest_route( 'vf/v1', '/open', array( 'methods' => 'POST', 'callback' => 'vf_open' ) );
		// wp.rest.public-write (high: always-true permission, callback checks nothing)
		register_rest_route(
			'vf/v1',
			'/write',
			array(
				'methods'             => 'POST',
				'callback'            => 'vf_write',
				'permission_callback' => '__return_true',
			)
		);
	}
);

function vf_open( $req ) {
	return true;
}

function vf_write( $req ) {
	update_option( 'vf_value', $req['v'] );
	return true;
}

// wp.csrf.ajax-no-nonce (public handler that changes data)
add_action( 'wp_ajax_nopriv_vf_save', 'vf_save' );
function vf_save() {
	update_option( 'vf_x', sanitize_text_field( wp_unslash( $_POST['x'] ?? '' ) ) );
	wp_die();
}

// wp.csrf.ajax-no-nonce + wp.authz.ajax-no-capability (logged-in handler, any subscriber can change settings)
add_action( 'wp_ajax_vf_admin', 'vf_admin' );
function vf_admin() {
	update_option( 'vf_y', 1 );
	wp_die();
}

// wp.rce.eval + wp.malware.obfuscated
function vf_eval() {
	eval( base64_decode( $_POST['c'] ) );
}

// wp.objinj.unserialize
function vf_unserialize() {
	return unserialize( $_COOKIE['d'] );
}

// wp.lfi.include
function vf_include() {
	include $_GET['page'] . '.php';
}

// wp.rce.shell
function vf_shell() {
	return shell_exec( 'ls ' . $_GET['dir'] );
}

// wp.extract-request
function vf_extract() {
	extract( $_POST );
}

// wp.open-redirect
function vf_redirect() {
	wp_redirect( $_GET['to'] );
	exit;
}

// wp.ssrf-file
function vf_ssrf() {
	return wp_remote_get( $_GET['url'] );
}

// wp.upload.raw
function vf_upload() {
	move_uploaded_file( $_FILES['f']['tmp_name'], '/tmp/upload' );
}

// secret.aws-access-key: the fake key lives in includes/generated-secret.php, written by tests/helpers.mjs
// (not committed literally, so GitHub secret scanning has nothing to flag)
?>
<!-- wp.csrf.form-no-nonce -->
<form method="post" action="">
	<input name="x">
</form>
