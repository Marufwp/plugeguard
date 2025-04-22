jQuery(document).ready(function ($) {
      let targetForm;
  
      $('.plugeguard-remove-button').on('click', function (e) {
          e.preventDefault();
          targetForm = $(this).closest('form');
          $('#plugeguard-confirm-modal').fadeIn();
      });
  
      $('#plugeguard-modal-cancel').on('click', function () {
          $('#plugeguard-confirm-modal').fadeOut();
      });
  
      $('#plugeguard-modal-confirm').on('click', function () {
          if (targetForm) {
              targetForm.submit();
          }
      });
  
      $('form[name="scan_code"]').on('submit', function () {
          $('.plugeguard-preloader').show();
          $('.scan-button').prop('disabled', true);
          startProgressBar();
      });
  
      function startProgressBar() {
          let percentage = 0;
          let interval = setInterval(function () {
              if (percentage >= 100) {
                  clearInterval(interval);
              } else {
                  percentage++;
                  $('.plugeguard-preloader .percentage').text(percentage + '%');
              }
          }, 100);
      }
  });