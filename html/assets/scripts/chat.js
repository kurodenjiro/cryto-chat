
/* ===================
    DOCUMENT HANDLERS
   =================== */

$(document).ready(function () {

  // Hide loading overlay

  $('#loading').hide(0);

  // Remove blur from credentials

  $('#credentials').removeClass('blur');

  // Handle group password strength

  $('#credentials input[name="groupPassword"]').on('keyup mouseup change paste', function () {

    var passwordStrength = 0;
    var passwordLetters = {};

    for (
      var i = 0;
      i < $(this).val().length;
      ++i
    ) {
      passwordLetters[$(this).val()[i]] = ( ( passwordLetters[$(this).val()[i]] || 0 ) + 1 );
      passwordStrength += ( 5 / passwordLetters[$(this).val()[i]] );
    };

    passwordStrength += ( (
      (
        ( $(this).val().match(/[a-z]/) ? 1 : 0 ) +
        ( $(this).val().match(/[A-Z]/) ? 1 : 0 ) +
        ( $(this).val().match(/[0-9]/) ? 1 : 0 ) +
        ( $(this).val().match(/[^a-zA-Z0-9]/) ? 1 : 0 )
      ) - 1
    ) * 10 );

    if (
      $(this).val().length < 1
    ) {
      passwordStrength = 0;
    };

    passwordStrength = Math.floor(
      passwordStrength > 100
      ? 100
      : passwordStrength
    );

    $('#credentials div.bar').css({
      'width' : Math.round( ( 306 / 100 ) * passwordStrength ) + 'px',
      'background-color' : 'rgba(' + ( 255 - Math.round( ( 255 / 100 ) * passwordStrength ) ) + ',' + Math.round( ( 255 / 100 ) * passwordStrength ) + ',0,1)',
    });

  });

  // Handle credendials

  $('#credentials button').on('click', function () {

    // Validate fields

    var errorCount = 0;

    if (
      $('#credentials input[name="userName"]').val().length < 1
    ) {
      ++errorCount;
      $('#credentials input[name="userName"]').addClass('error');
    } else {
      $('#credentials input[name="userName"]').removeClass('error');
    };

    if (
      $('#credentials input[name="groupName"]').val().length < 1
    ) {
      ++errorCount;
      $('#credentials input[name="groupName"]').addClass('error');
    } else {
      $('#credentials input[name="groupName"]').removeClass('error');
    };

    if (
      $('#credentials input[name="groupPassword"]').val().length < 1
    ) {
      ++errorCount;
      $('#credentials input[name="groupPassword"]').addClass('error');
    } else {
      $('#credentials input[name="groupPassword"]').removeClass('error');
    };

    if (
      errorCount === 0
    ) {

      // Set credentials

      ChatCrypt.setCredentials($('#credentials input[name="userName"]').val(), $('#credentials input[name="groupName"]').val(), SHA256($('#credentials input[name="groupPassword"]').val()));

      // Show chat

      $('#chat').show(0);

      // Add member username

      $('#chat div.members').append($('<div />').addClass('member').addClass(CONFIG.theme).text($('#credentials input[name="userName"]').val()));

      // Reset credentials

      $('#credentials button').unbind('click');

      $('#credentials input[name="userName"]').val('');
      $('#credentials input[name="groupName"]').val('');
      $('#credentials input[name="groupPassword"]').val('');

      // Remove credentials

      $('#credentials').remove();

      // Connect to wss

      ChatCrypt.wssConnect();

    };

  });

  // Handle credentials change theme

  $('#credentials div.theme span[data-theme]').click(function () {
    changeTheme($(this).attr('data-theme'));
  });

  // Handle message input

  $('#chat div.input span textarea[name="message"]').on('keydown', function ( event ) {
    if (
      event.keyCode == 13 &&
      event.shiftKey == false
    ) {

      event.preventDefault();

      if (
        $(this).val().length > 0 &&
        ! $(this).val().match(/^[\r\n]+$/)
      ) {
        ChatCrypt.sendMessageGroup($(this).val());
      };

      $(this).val('');

    };
  });

  $('#chat div.input button').click(function () {
    if (
      $('#chat div.input span textarea[name="message"]').val().length > 0 &&
      ! $('#chat div.input span textarea[name="message"]').val().match(/^[\r\n]+$/)
    ) {
      ChatCrypt.sendMessageGroup($('#chat div.input span textarea[name="message"]').val());
      $('#chat div.input span textarea[name="message"]').val('');
    };
  });

});

/* ============
    CONNECTING
   ============ */

// Show connecting overlay

function showConnecting () {
  $('#chat').addClass('blur');
  $('#connecting').show(0);
};

// Hide connecting overlay

function hideConnecting () {
  $('#chat').removeClass('blur');
  $('#connecting').hide(0);
};

/* ==============
    SHOW MESSAGE
   ============== */

function showMessage ( member, message, members ) {

  $('#chat div.conversation').append($('<div />').addClass('message').addClass(CONFIG.theme).html('<b>&lt;' + member + '&gt;</b> ' + message.escapeHtml().replace(/\r?\n/gmi, '<br />') + (
    typeof(members) === 'number'
    ? '<sub class="noselect">' + members + '</sub>'
    : ''
  )));

  $('#chat div.conversation').animate({
    'scrollTop' : $('#chat div.conversation').get(0).scrollHeight,
  }, 0);

};

/* ======================
    UPDATE GROUP MEMBERS
   ====================== */

function updateGroupMembers ( members ) {

  // Remove non-existing members

  $('#chat div.members div.member[data-member]').each(function () {
    if (
      typeof(members[$(this).attr('member')]) === 'undefined'
    ) {
      $(this).remove();
    };
  });

  // Add new members

  Object.keys(members).map(function ( member, index ) {
    if (
      $('#chat div.members div.member[data-member="' + member + '"]').length === 0
    ) {
      $('#chat div.members').append($('<div />').addClass('member').addClass(CONFIG.theme).attr('data-member', member).text(members[member]));
    };
  });

};

/* ==============
    CHANGE THEME
   ============== */

function changeTheme ( theme ) {

  CONFIG.theme = theme;

  $('html, body').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#advertisement').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#chat div.conversation').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#chat div.conversation div.message').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#chat div.members span').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#chat div.members div.member').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#chat div.input').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#chat div.input span textarea[name="message"]').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#chat div.input button').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#credentials').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#credentials > span').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#credentials input[type="text"]').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#credentials input[type="password"]').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#credentials button').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#credentials div.strength').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#credentials div.theme').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);
  $('div#loading span, div#connecting span').removeClass('matrix').removeClass('white').removeClass('yellow').addClass(theme);

};

/* =============
    ESCAPE HTML
   ============= */

(function(){

  function escapeHtml () {
    return this.replace(/[&<>"'\/]/g, function (s) {
      var entityMap = {
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': '&quot;',
          "'": '&#39;',
          "/": '&#x2F;'
        };

      return entityMap[s];
    });
  }

  if (typeof(String.prototype.escapeHtml) !== 'function') {
    String.prototype.escapeHtml = escapeHtml;
  }

})();
