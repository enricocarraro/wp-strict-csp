<?php

/**
 * Plugin initialization file
 *
 * @package   Google\WP_Strict_CSP
 * @copyright 2020 Google LLC
 * @license   GNU General Public License, version 2
 * @link      not-yet
 *
 * @wordpress-plugin
 * Plugin Name: Strict Content Security Policy
 * Plugin URI:  not-yet
 * Description: Enables Strict Content Security Policy header, injects nonces in every wordpress generated script tag.
 * Version:     0.0.1
 * Author:      Google
 * Author URI:  https://opensource.google.com/
 * License:     GNU General Public License v2 (or later  )
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 */

 // Inject nonces only in the admin area
if ( is_admin() ) {
    add_filter( 'inline_script_attributes', function ( $attr ) {
        if ( strpos( $attr, ' nonce="' ) === false ) {
            $attr .= sprintf( ' nonce="%s"', esc_attr( get_nonce() ) );
        }
        return $attr;
    } );
    add_filter( 'script_loader_tag', 'add_csp_nonce', 10, 2 );
}

// This action adds CSP headers to the admin area responses
add_action( 
    'admin_init',
    function () {
        if ( ! wp_doing_ajax() ) {
            header( "Content-Security-Policy-Report-Only: script-src 'self' 'nonce-" . esc_attr( get_nonce() ) . "' 'unsafe-eval' 'strict-dynamic' https: http:;" );
        }
    }
);

// Adds nonces to script tags that don't have one.
function add_csp_nonce( $tag, $handle )
{
    $nonce = esc_attr( get_nonce() );
    $pattern = '/<script\b(?![^>]*\b' . $nonce . '\b)[^>]*/si';
    $replacement = sprintf( '${0} nonce="%s"', $nonce );
    return preg_replace( $pattern, $replacement, $tag );
}


// Generates a secure hash and sets 'csp_nonce' in the $GLOBALS associative array
function get_nonce()
{
    if ( !isset( $GLOBALS['csp_nonce'] ) ) {
        require_once( ABSPATH . 'wp-includes/class-phpass.php' );
        $hasher = new PasswordHash( 8, /* portable_hashes= */ false );
        $GLOBALS['csp_nonce'] = md5( $hasher->get_random_bytes( 100 ) );
    }
    return $GLOBALS['csp_nonce'];
}
