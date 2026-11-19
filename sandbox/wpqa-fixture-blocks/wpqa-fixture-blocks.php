<?php
/**
 * Plugin Name: WPQA fixture blocks (sandbox only)
 * Description: One dynamic block with typed attributes, for the toolkit's block-editor round-trip test. Install ONLY on a disposable sandbox.
 * Version: 1.0.0
 * Requires at least: 6.5
 * Requires PHP: 8.1
 * Text Domain: wpqa-fixture-blocks
 * Update URI: false
 */

defined( 'ABSPATH' ) || exit;

add_action(
	'init',
	static function () {
		register_block_type( __DIR__ . '/blocks/notice' );
	}
);
