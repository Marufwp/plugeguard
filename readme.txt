=== PlugeGuard ===
Contributors: Plugesoft Team
Tags: security, scanner, firewall, remove hidden passwords, credentials scanner 
Requires PHP: 8.0
Requires at least: 5.6
Tested up to: 6.8
Stable tag: 1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Scans your WordPress installation for hardcoded login credentials (usernames/passwords) and allows safe removal from PHP files.

== Description ==
PlugeGuard enhances WordPress security by detecting hidden or hardcoded login credentials within your PHP files. It provides an admin UI to review and remove potential backdoors or malicious injections manually.

Features:
* Deep file scanning for hidden credentials
* Secure file viewing and removal
* Lightweight and easy to use
* Fully compatible with modern WordPress standards

== Installation ==
1. Upload the plugin to the `/wp-content/plugins/` directory
2. Activate through the 'Plugins' menu
3. Go to PlugeGuard Setting > PlugeGuard to scan your site

== Frequently Asked Questions ==
= Does it delete files? =
No. It only removes detected credential lines, not entire files.

= Will it detect all types of hidden credentials? =
It detects known patterns, especially those wrapped with specific indicators. Obfuscated or encrypted methods may require manual review.

== Changelog ==
= 1.0 =
* Initial release of PlugeGuard

== Upgrade Notice ==
= 1.0 =
First stable release.
