<?php
/**
 * Plugin initialization file
 *
 * @package   Google\WP_Strict_CSP
 * @copyright 2020 Google LLC
 * @license   GNU General Public License, version 2
 *
 * @wordpress-plugin
 * Plugin Name: Strict Content Security Policy
 * Description: Enables Strict Content Security Policy Header, injects nonces in every WordPress generated script tag.
 * Version:     0.0.1
 * Author:      Google
 * Author URI:  https://opensource.google.com/
 * License:     GNU General Public License v2 (or later)
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 */


add_action(
	'admin_init',
	function () {
		header( "Content-Security-Policy-Report-Only: object-src 'none'; script-src 'nonce-" . esc_attr( get_nonce() ) . "' 'unsafe-eval' 'strict-dynamic' https: http:;" );
	}
);

// Inject nonces only in the admin area
if ( is_admin() ) {


	add_filter(
		'wp_script_attributes',
		function ( $attr ) {
			if ( ! array_key_exists( 'nonce', $attr ) ) {
				$attr['nonce'] = esc_attr( get_nonce() );
			}
			return $attr;
		}
	);
}


// Generates a secure hash and sets 'csp_nonce' in $GLOBALS
function get_nonce() {
	if ( ! isset( $GLOBALS['csp_nonce'] ) ) {
		require_once( ABSPATH . 'wp-includes/class-phpass.php' );
		$hasher               = new PasswordHash( 8, /* portable_hashes= */ false );
		$GLOBALS['csp_nonce'] = md5( $hasher->get_random_bytes( 100 ) );
	}
	return $GLOBALS['csp_nonce'];
}
