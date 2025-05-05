<?php
/**
 * Plugin Name: PlugeGuard
 * Plugin URI: https://wordpress.org/plugins/plugeguard/
 * Description: Scans your entire WordPress site for hidden or hardcoded usernames and passwords, helping you identify and safely remove potential security threats.
 * Version: 1.0
 * Author: maruffwp
 * Author URI: https://plugesoft.com
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: plugeguard
 * Requires PHP: 8.0
 * Requires at least: 5.6
 * Tested up to: 6.5
 * Stable tag: 1.0
 * Tags: security, scanner, firewall, remove hidden passwords, credentials scanner
 *
 * @package PlugeGuard
 */

if (!defined('ABSPATH')) exit;

/**
 * Class PlugeGuard
 * Handles scanning, removal, and updating of hardcoded credentials in PHP files across the WordPress installation.
 */
class PlugeGuard {

    /**
     * Constructor. Hooks into WordPress actions.
     */
    public function __construct() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_post_plugeguard_remove_code', [$this, 'remove_code']);
        add_action('admin_post_plugeguard_update_file', [$this, 'update_file']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('admin_init', [$this, 'handle_activation_redirect']);
    }

    /**
     * Handles plugin activation redirect with security nonce check.
     */
    public function handle_activation_redirect() {
        if (get_option('plugeguard_redirect_on_activate')) {
            $activation_url = get_option('plugeguard_redirect_on_activate');
            delete_option('plugeguard_redirect_on_activate');
            
            $nonce = isset($_GET['plugeguard_activation_nonce']) ? sanitize_key(wp_unslash($_GET['plugeguard_activation_nonce'])) : '';
            $nonce = sanitize_text_field($nonce);
            
            if (!empty($nonce) && wp_verify_nonce($nonce, 'plugeguard_activation_action')) {
                if (!isset($_GET['activate-multi'])) {
                    wp_safe_redirect($activation_url);
                    exit;
                }
            } else {
                wp_die('Security check failed. Invalid request.');
            }
        }
    }

    /**
     * Enqueues necessary CSS and JavaScript assets for the admin interface.
     */
    public function enqueue_assets() {
        wp_enqueue_code_editor(['type' => 'text/x-php']);
        wp_enqueue_script('wp-theme-plugin-editor');
        wp_enqueue_style('wp-codemirror');
    
        wp_enqueue_style(
            'plugeguard-css', 
            plugin_dir_url(__FILE__) . 'assets/css/plugeguard.css',
            [],
            filemtime(plugin_dir_path(__FILE__) . 'assets/css/plugeguard.css')
        );
    
        wp_enqueue_script(
            'plugeguard-js', 
            plugin_dir_url(__FILE__) . 'assets/js/plugeguard.js', 
            ['jquery'], 
            filemtime(plugin_dir_path(__FILE__) . 'assets/js/plugeguard.js'), 
            true
        );
    
        wp_enqueue_script(
            'plugeguard-editor-js',
            plugin_dir_url(__FILE__) . 'assets/js/plugeguard-editor.js',
            ['jquery', 'wp-code-editor'],
            filemtime(plugin_dir_path(__FILE__) . 'assets/js/plugeguard-editor.js'),
            true
        );
    
        wp_localize_script('plugeguard-editor-js', 'plugeguard_data', [
            'highlight_line' => $this->highlight_line, 
        ]);
    }

    /**
     * Adds the PlugeGuard admin menu page.
     */
    public function add_admin_menu() {
        add_menu_page(
            esc_html__('PlugeGuard', 'plugeguard'),
            esc_html__('PlugeGuard', 'plugeguard'),
            'manage_options',
            'plugeguard',
            [$this, 'scanner_page'],
            'dashicons-shield',
            100
        );
    }

    /**
     * Displays the main scanner page, showing scan results and removal options.
     */
    public function scanner_page() {
        $this->results = $this->scan_directory(get_theme_root(__FILE__));

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('PlugeGuard: Hidden Login Scanner', 'plugeguard') . '</h1>';
        echo '<p>' . esc_html__('Scans your entire site for hidden or hardcoded usernames and passwords, helping you identify and safely remove potential security threats.', 'plugeguard') . '</p>';
        echo '<strong>' . esc_html__('We strongly recommended to take a full site backup before scanning or removing any code.', 'plugeguard') . '</strong>';
        echo '<form name="scan_code" method="post">';
        wp_nonce_field('plugeguard_scan_action', 'plugeguard_nonce');
        echo '<input type="submit" name="scan_code" class="button scan-button" value="' . esc_attr__('Start Scan', 'plugeguard') . '">';
        echo '</form><br>';

        if (!empty($this->results)) {
            echo '<p>' . esc_html__('The following hidden credentials were found. You can remove them by clicking the "Remove" button:', 'plugeguard') . '</p>';
            echo '<table class="widefat fixed"><thead><tr><th>' . esc_html__('File', 'plugeguard') . '</th><th>' . esc_html__('Line', 'plugeguard') . '</th><th>' . esc_html__('Hidden User Code', 'plugeguard') . '</th><th>' . esc_html__('Actions', 'plugeguard') . '</th></tr></thead><tbody>';
            
            foreach ($this->results as $item) {
                $code_escaped = esc_html($item['code']);
                $file_encoded = urlencode($item['file']);
                $remove_url = esc_url(admin_url('admin-post.php'));
                
                echo '<tr>';
                echo '<td>' . esc_html($item['file']) . '</td>';
                echo '<td>' . esc_html($item['line']) . '</td>';
                echo '<td><code>' . esc_html( $code_escaped ) . '</code></td>';
                echo '<td>';
                echo '<form method="post" action="' . esc_url( $remove_url ) . '" style="display:inline; margin-left: 0px;">';
                echo '<input type="hidden" name="action" value="plugeguard_remove_code">';
                echo '<input type="hidden" name="file" value="' . esc_attr($file_encoded) . '">';
                echo '<input type="hidden" name="line" value="' . esc_attr($item['line']) . '">';
                wp_nonce_field('plugeguard_remove_action', 'plugeguard_nonce');
                echo '<button type="button" class="button button-danger plugeguard-remove-button">' . esc_html__('Remove', 'plugeguard') . '</button>';
                echo '</form>';
                echo '</td>';
                echo '</tr>';
            }
            
            echo '</tbody></table>';
        } else {
            echo '<p style="font-size: 18px;">' . esc_html__('No suspicious hardcoded credentials found.', 'plugeguard') . '</p>';
        }

        $help_text = sprintf(
            /* translators: 1: Email link, 2: LinkedIn profile link */
            esc_html__('Need help? Email us at %1$s or connect via %2$s.', 'plugeguard'),
            '<a href="mailto:support@plugesoft.com">support@plugesoft.com</a>',
            '<a href="https://www.linkedin.com/in/maruffwp/">LinkedIn</a>'
        );

        echo '<p>' . wp_kses_post($help_text) . '</p>';
        echo '</div>';
        include_once plugin_dir_path(__FILE__) . 'templates/modal-preloader.php';
    }

    /**
     * Scans a directory recursively for PHP files containing hardcoded credentials.
     *
     * @param string $dir Directory path to scan.
     * @return array Scan results.
     */
    public function scan_directory($dir) {
        $results = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));

        foreach ($iterator as $file) {
            if ($file->isFile() && pathinfo($file, PATHINFO_EXTENSION) === 'php') {
                $lines = file($file->getPathname());
                foreach ($lines as $num => $line) {
                    if (preg_match('/\$(username|user|admin|password)\s*=\s*[\'"]([^\'"]+)[\'"]\s*;/', $line)) {
                        $results[] = [
                            'file' => $file->getPathname(),
                            'line' => $num + 1,
                            'code' => trim($line)
                        ];
                    }
                }
            }
        }

        return $results;
    }

    /**
     * Handles the removal of a specific line of code from a file.
     */
    public function remove_code() {
        if (!current_user_can('manage_options') || !isset($_POST['plugeguard_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['plugeguard_nonce'])), 'plugeguard_remove_action')) {
            wp_die(esc_html__('Unauthorized', 'plugeguard'));
        }              

        if (!isset($_POST['file']) || !isset($_POST['line'])) {
            wp_die(esc_html__('Invalid request', 'plugeguard'));
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $file = ! empty( $_POST['file'] ) ? sanitize_text_field( urldecode( wp_unslash( $_POST['file'] ) ) ) : '';
        $file = str_replace(['../', '..\\'], '', $file);
        $normalized_path = wp_normalize_path(get_theme_root(__FILE__) . '/' . $file);
        $line_number = (int)$_POST['line'];

        if (file_exists($file)) {
            $lines = file($file);
            if (isset($lines[$line_number - 1])) {
                unset($lines[$line_number - 1]);
                file_put_contents($file, implode('', $lines));
            }
        }

        wp_safe_redirect(admin_url('admin.php?page=plugeguard'));
        exit;
    }

    /**
     * Updates the contents of a given file.
     */
    public function update_file() {
        if (!current_user_can('manage_options') || !isset($_POST['plugeguard_nonce']) || !wp_verify_nonce(sanitize_key(wp_unslash($_POST['plugeguard_nonce'])), 'plugeguard_update_action')) {
            wp_die(esc_html__('Unauthorized', 'plugeguard'));
        }        

        if (!isset($_POST['file']) || !isset($_POST['content'])) {
            wp_die(esc_html__('Invalid request', 'plugeguard'));
        }

        if (isset($_POST['file'])) {
            $file = sanitize_file_name(wp_unslash($_POST['file']));
        }
        
        if (isset($_POST['content'])) {
            $content = sanitize_textarea_field(wp_unslash($_POST['content']));
        }
        
        if (file_exists($file)) {
            file_put_contents($file, $content);
            wp_safe_redirect(admin_url('admin.php?page=plugeguard-view-file&file=' . urlencode($file) . '&updated=true'));
            exit;
        }

        wp_safe_redirect(admin_url('admin.php?page=plugeguard'));
        exit;
    }
}

new PlugeGuard();

/**
 * Adds a 'Settings' link on the plugin listing page.
 *
 * @param array $links Existing plugin action links.
 * @return array Modified links.
 */
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'plugeguard_plugin_action_links');

function plugeguard_plugin_action_links($links) {
    $settings_link = '<a href="' . admin_url('admin.php?page=plugeguard') . '">Settings</a>';
    array_unshift($links, $settings_link);
    return $links;
}
