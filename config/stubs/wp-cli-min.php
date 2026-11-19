<?php
/**
 * Minimal WP-CLI declarations for PHPStan (scanFiles only, never executed).
 * Used when the full php-stubs/wp-cli-stubs package is not installed in the toolkit.
 */

class WP_CLI {
	/** @param string $message */
	public static function log( $message ) {}
	/** @param string $message */
	public static function line( $message = '' ) {}
	/** @param string $message */
	public static function success( $message ) {}
	/**
	 * @param string $message
	 * @param string|bool $group
	 */
	public static function debug( $message, $group = false ) {}
	/** @param string|\WP_Error|\Exception $message */
	public static function warning( $message ) {}
	/**
	 * @param string|\WP_Error|\Exception $message
	 * @param bool|int $exit
	 * @return ($exit is false ? void : never)
	 */
	public static function error( $message, $exit = true ) {}
	/** @param array<string> $message_lines */
	public static function error_multi_line( $message_lines ) {}
	/** @return never */
	public static function halt( $return_code ) {}
	/**
	 * @param string $question
	 * @param array<string,mixed> $assoc_args
	 */
	public static function confirm( $question, $assoc_args = array() ) {}
	/**
	 * @param string $string
	 * @return string
	 */
	public static function colorize( $string ) { return ''; }
	/**
	 * @param string $name
	 * @param callable|class-string|object $callable
	 * @param array<string,mixed> $args
	 * @return bool
	 */
	public static function add_command( $name, $callable, $args = array() ) { return true; }
	/**
	 * @param string $command
	 * @param array<string,mixed> $options
	 * @return mixed
	 */
	public static function runcommand( $command, $options = array() ) { return null; }
	/**
	 * @param string $when
	 * @param callable $callback
	 */
	public static function add_hook( $when, $callback ) {}
	/** @return mixed */
	public static function get_config( $key = null ) { return null; }
}

abstract class WP_CLI_Command {
	public function __construct() {}
}
