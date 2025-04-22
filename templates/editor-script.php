<script>
    jQuery(document).ready(function ($) {
        const editor = wp.codeEditor.initialize($('#plugeguard-editor'), {
            codemirror: {
                mode: 'application/x-httpd-php',
                indentUnit: 4,
                tabSize: 4,
                lineNumbers: true,
                lineWrapping: true,
                gutters: ["CodeMirror-linenumbers"]
            }
        }).codemirror;

        <?php if ($highlight_line): ?>
        editor.addLineClass(<?php echo esc_js( $highlight_line - 1 ); ?>, 'background', 'highlight-line');
        editor.scrollIntoView({ line: <?php echo esc_js( $highlight_line - 1 ); ?> });
        <?php endif; ?>
    });
</script>