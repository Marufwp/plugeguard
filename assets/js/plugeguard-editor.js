/**
 * PlugeGuard Editor Script
 * Initializes the WordPress Code Editor on the PlugeGuard file editor,
 * highlights the specified line (if provided), and scrolls it into view.
 *
 * @package PlugeGuard
 */

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
  
      if (typeof plugeguard_data !== 'undefined' && plugeguard_data.highlight_line) {
          editor.addLineClass(plugeguard_data.highlight_line - 1, 'background', 'highlight-line');
          editor.scrollIntoView({ line: plugeguard_data.highlight_line - 1 });
      }
  });
  