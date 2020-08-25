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
 * Text Domain: feature-policy
 */

if ( is_admin() ) {
    add_filter( 'inline_script_attributes', function ( $attr ) {
        if ( strpos( $attr, ' nonce="' ) === false ) {
            return 'nonce="' . get_nonce() . '" ' . $attr;
        }
        return $attr;
    } );
    add_filter( 'script_loader_tag', 'add_csp_nonce', 10, 2 );
}

// This action adds Strict CSP to the admin area
add_action( 
    'admin_init',
    function () {
        if ( wp_doing_ajax() || !empty( $_POST ) ) {
            return;
        }
        header( "Content-Security-Policy-Report-Only: script-src 'self' 'nonce-" . get_nonce() . "' 'unsafe-eval' 'strict-dynamic' https: http:;" );
    }
 );

function add_csp_nonce( $tag, $handle )
{
    $nonce = get_nonce();
    if ( strpos( $tag, ' nonce="' ) === false ) {
        $tag = str_replace( '<script ', '<script nonce="' . $nonce . '" ', $tag );
    } else if ( substr_count( $tag, ' nonce="' ) !== substr_count( $tag, '<script' ) ) {
        $tag = str_replace( ' nonce="' . $nonce . '"', '', $tag );
        $tag = str_replace( '<script ', '<script nonce="' . $nonce . '" ', $tag );
    }
    return $tag;
}

function get_nonce()
{
    if ( !isset( $GLOBALS['csp_nonce'] ) ) {
        require_once( ABSPATH . 'wp-includes/class-phpass.php' );
        $hasher = new PasswordHash( 8, false );
        $nonce = md5( $hasher->get_random_bytes( 100, false ) );
        $GLOBALS['csp_nonce'] = esc_attr( $nonce  );
    }
    return $GLOBALS['csp_nonce'];
}
