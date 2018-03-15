<?php

/**
 * Plugin Name: Auth0 Profile (BETA)
 * Description: Beta test for additional profile data
 * Version: 0.1.0
 * Author: Auth0
 * Author URI: https://auth0.com
 */

define( 'WPA0_PROFILE_PLUGIN_FILE', __FILE__ );
define( 'WPA0_PROFILE_PLUGIN_DIR', trailingslashit( plugin_dir_path( __FILE__ ) ) );
define( 'WPA0_PROFILE_PLUGIN_URL', trailingslashit( plugin_dir_url( __FILE__ ) ) );
define( 'WPA0_PROFILE_VERSION', '0.1.0' );
define( 'WPA0_PROFILE_CACHE_GROUP', 'wp_auth0_profile' );
define( 'WPA0_PROFILE_TOKEN_URL_PARAM', 'auth0-profile-token' );

/**
 * Check if Login by Auth0 is installed and active
 * Required for this plugin to function
 *
 * @return bool
 */
function a0_profile_have_wp_auth0() {
    return class_exists( 'WP_Auth0' );
}

/**
 * Catch an incoming Auth0 profile update request
 */
function a0_profile_hook_init() {

    // Nothing to do or WP-Auth0 not active
    if ( empty( $_GET[ 'auth0-profile' ] ) || ! a0_profile_have_wp_auth0() ) {
        return;
    }

    if ( ! empty( $_GET[ 'code' ] ) ) {

        $options = WP_Auth0_Options::Instance();
        $redirect_url = get_edit_profile_url();

        // Exchange auth code for an access token
        $exch_resp = WP_Auth0_Api_Client::get_token(
            $options->get( 'domain' ),
            $options->get( 'client_id' ),
            $options->get( 'client_secret' ),
            'authorization_code',
            array(
                'redirect_uri' => home_url(),
                'code' => $_GET[ 'code' ],
            )
        );

        $exch_resp_code = (int) wp_remote_retrieve_response_code( $exch_resp );
        $exch_resp_body = wp_remote_retrieve_body( $exch_resp );
        $exch_resp_body = json_decode( $exch_resp_body );

        // Catch unsuccessful responses
        if ( 200 !== $exch_resp_code || empty( $exch_resp_body->access_token ) ) {
            wp_safe_redirect( add_query_arg( WPA0_PROFILE_TOKEN_URL_PARAM, 0, $redirect_url ) );
            WP_Auth0_ErrorManager::insert_auth0_error( __FUNCTION__, $exch_resp_body . ' - Code: ' . $exch_resp_code );
            exit;
        }

        // Redirect back to the profile if we have an access token
        wp_safe_redirect( add_query_arg( WPA0_PROFILE_TOKEN_URL_PARAM, $exch_resp_body->access_token, $redirect_url ) );
        exit;
    }
}

add_action( 'init', 'a0_profile_hook_init' );

/**
 * Exchange a successful access token for userinfo to store
 */
function a0_profile_hook_admin_init() {

    // Nothing to do or WP-Auth0 not active
    if ( empty( $_GET[ WPA0_PROFILE_TOKEN_URL_PARAM ] ) || ! a0_profile_have_wp_auth0() ) {
        return;
    }

    $options = WP_Auth0_Options::Instance();

    // Get user profile with access token
    $ui_resp = WP_Auth0_Api_Client::get_user_info(
        $options->get( 'domain' ),
        $_GET[ WPA0_PROFILE_TOKEN_URL_PARAM ]
    );

    $ui_resp_code = (int) wp_remote_retrieve_response_code( $ui_resp );
    $ui_resp_body = wp_remote_retrieve_body( $ui_resp );
    $ui_resp_body = json_decode( $ui_resp_body );

    // Catch unsuccessful responses
    if ( 200 !== $ui_resp_code || empty( $ui_resp_body ) ) {
        WP_Auth0_ErrorManager::insert_auth0_error( __FUNCTION__, $ui_resp_body . ' - Code: ' . $ui_resp_code );
        return;
    }

    $user_repo = new WP_Auth0_UsersRepo( $options );
    $user_repo->update_auth0_object( get_current_user_id(), $ui_resp_body );

    wp_safe_redirect( get_edit_profile_url() );
    exit;
}

add_action( 'admin_init', 'a0_profile_hook_admin_init' );

/**
 * Shown when someone is editing their own profile
 *
 * @param $user
 */
function a0_profile_hook_show_user_profile( $user ) {

    if ( ! a0_profile_have_wp_auth0() ) {
        return;
    }

    $auth0_user = get_auth0userinfo( $user->ID );
    $options = WP_Auth0_Options::Instance();

    if ( ! $auth0_user ) {

        echo '<h3>Auth0</h3>';

        $auth_url = sprintf(
            'https://%s/authorize?response_type=code&client_id=%s&scope=%s&redirect_uri=%s',
            $options->get( 'domain' ),
            $options->get( 'client_id' ),
            implode( '%20', [ 'openid', 'email', 'email_verified', 'profile' ] ),
            urlencode( add_query_arg( 'auth0-profile', 1, home_url() ) )
        );

        if ( isset( $_GET[ WPA0_PROFILE_TOKEN_URL_PARAM ] ) && empty( $_GET[ WPA0_PROFILE_TOKEN_URL_PARAM ] ) ) {
            printf(
                '<p><strong>%s</strong></p>',
                __( 'Login attempt was unsuccessful. Please try again or see a site admin.', 'wp-auth0-profile' )
            );
        }

        printf(
            '<a href="%s" class="button">%s</a>',
            esc_url( $auth_url ),
            __( 'Login with Auth0', 'wp-auth0-profile' )
        );

    } else if ( ! current_user_can( 'edit_users' ) ) {

        // Users who can edit_users will see all the data
        // @see a0_profile_hook_edit_user_profile()
        printf(
            '<h3>Auth0</h3><p>%s: <code>%s</code></p>',
            __( 'Connected to Auth0 user ID', 'wp-auth0-profile' ),
            $auth0_user->sub
        );
    }
}

add_action( 'show_user_profile', 'a0_profile_hook_show_user_profile' );

/**
 * Shown when a profile is edited by an admin
 *
 * @param $user
 */
function a0_profile_hook_edit_user_profile( $user ) {

    // Nothing to do or not authorized to view all Auth0 data
    if ( ! a0_profile_have_wp_auth0() || ! current_user_can( 'edit_users' ) ) {
        return;
    }

    if ( $auth0_user = get_auth0userinfo( $user->ID ) ) {

        echo '<h3>Auth0</h3><table class="form-table">';

        foreach ( $auth0_user as $key => $val ) {

            if ( is_array( $val ) || is_object( $val ) ) {
                continue;
            }

            // Pretty up and sanitize output
            switch ( $key ) {

                case 'email_verified':
                    $sanitized_val = empty( $val )
                        ? '<span class="dashicons dashicons-no-alt"></span>'
                        : '<span class="dashicons dashicons-yes"></span>';
                    break;

                case 'picture':
                    $sanitized_val = sprintf(
                        '<img width="50" src="%s">',
                        esc_url( $val )
                    );
                    break;

                default:
                    $sanitized_val = '<code>' . sanitize_text_field( $val ) . '</code>';
            }

            printf(
                '<tr><th scope="row"><strong>%s</strong></th><td>%s</td></tr>',
                sanitize_text_field( $key ),
                $sanitized_val
            );
        }

        echo '</table>';
    }
}

add_action( 'edit_user_profile', 'a0_profile_hook_edit_user_profile' );
add_action( 'show_user_profile', 'a0_profile_hook_edit_user_profile' );