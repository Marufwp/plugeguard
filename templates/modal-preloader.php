<?php
/**
 * Modal and Preloader Template
 *
 * Provides the HTML for the PlugeGuard preloader spinner and the confirmation modal.
 *
 * @package PlugeGuard
 */

if (!defined('ABSPATH')) exit;
?>
<div class="plugeguard-preloader">
    <div class="progress-container">
        <div class="progress-bar"></div>
        <div class="percentage">0%</div>
    </div>
</div>

<div id="plugeguard-confirm-modal">
    <div class="modal-content">
        <p>Are you sure you want to remove this line?</p>
        <button id="plugeguard-modal-confirm" class="button button-primary">Yes, Remove</button>
        <button id="plugeguard-modal-cancel" class="button">Cancel</button>
    </div>
</div>
