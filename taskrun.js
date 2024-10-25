/**
 * Checks for new emails for each user listed in the Google Sheet,
 * processes them according to user-defined rules,
 * and forwards them to Slack if they match the rules.
 */
function checkmail() {
  var scriptProperties = PropertiesService.getScriptProperties();
  var data = getGmailTokenKey();

  for (var i = 0; i < data.length; i++) {
    var userEmail = data[i];
    //Retrieves specified files for a user from GCS and saves their content to script properties.
    // insead of retrives in taskrun, when giiSlacker commit will get from GCS 
    //saveGCSDataToScriptProperties(userEmail);

    var tokenKey = 'GMAIL_AUTH_TOKEN_' + userEmail;
    var authToken = JSON.parse(scriptProperties.getProperty(tokenKey));
    if (!authToken) {
      console.log('No auth token found for user: ' + userEmail);
      continue;
    } else {
      console.log('authToken. tokenKey is ' + tokenKey);
    }

    // Attempt to get emails using the current access token, refresh if expired
    var emails = [];
    try {
      emails = fetchEmails(authToken.accessToken, userEmail, authToken.refreshToken, 0);
    } catch (error) {
      console.error('Error fetching emails for user: ' + userEmail + ' - ' + error);
      continue;
    }

    if (emails.length === 0) {
      console.log('No new emails for user: ' + userEmail);
      continue;
    }

    // Get Slack tokens for the user
    var slackTokenKey = 'SLACK_AUTH_TOKEN_' + userEmail;
    var slackTokens = JSON.parse(scriptProperties.getProperty(slackTokenKey));
    // Get it from GCS instead
    //var slackTokens = getPropertyFromGCS(userEmail, slackTokenKey);

    // Loop through each workspace ID in the slack tokens
    for (var workspaceId in slackTokens) {
      console.log('workspaceId is ', workspaceId, ', and slackTokens[workspaceId] name is', slackTokens[workspaceId].workspaceName);
      var workspaceName = slackTokens[workspaceId].workspaceName;
      var slackToken = slackTokens[workspaceId].accessToken;
      var userRules = getUserRulesForWorkspace(userEmail, workspaceId); // New function to get rules for specific workspace

      var lastMailIdKey = 'LAST_MAIL_ID_' + userEmail;
      var newestMailTimestamp = 0; // Initialize to track the newest email's timestamp
      var forwarded = false;
      var lastMailTimestamp_sp = parseInt(scriptProperties.getProperty(lastMailIdKey)) || 0;

      for (var j = 0; j < emails.length; j++) {
        var lastMailTimestamp = parseInt(emails[j].internalDate); // internalDate is in milliseconds
        if (Math.floor(lastMailTimestamp / 1000) < lastMailTimestamp_sp) {
          //console.log('mail lastMailTimestamp is older than lastMailIdKey.', Math.floor(lastMailTimestamp / 1000), ', lastMailTimestamp_sp ', lastMailTimestamp_sp);
          continue;
        }

        if (lastMailTimestamp > newestMailTimestamp) {
          newestMailTimestamp = lastMailTimestamp;
        }

        //console.log('lastMailTimestamp is ', lastMailTimestamp, ' ,mails[j].internalDate is ', emails[j].internalDate);

        // Extract email content
        const emailContent = extractEmailContentFromJson(emails[j], authToken.accessToken, userEmail);
        var matchedTargets = [];  // Initialize empty objects

        for (var ruleName in userRules) {
          // Get slackTarget for each rule
          var slackTarget = ruleApplies(userRules[ruleName], emailContent, userEmail);

          if (slackTarget) {
            if (Array.isArray(slackTarget)) {
              slackTarget.forEach(function (target) {
                if (target.includes('_')) {
                  let [id, type] = target.split('_');
                  matchedTargets.push(id);
                } else {
                  console.warn('Invalid slackTarget format: ' + target);
                }
              });
            } else {
              console.warn('slackTarget is not an array for rule ' + ruleName);
            }
          } else {
            console.log('slackTarget is null for ' + ruleName);
          }
        }

        if (matchedTargets && matchedTargets.length > 0) {
          //console.log('checkmail send users is ' + matchedTargets);
          var uniqueTargetsUser = deduplicateTargets(matchedTargets);

          // task get attachment file here for tageted mail only
          /** start get attachment file */
          const userConfigKey = 'CONFIG_' + userEmail;
          var userConfig = JSON.parse(scriptProperties.getProperty(userConfigKey));
          var userAttachConfig = userConfig["GMAIL_CONFIG_ATTACHMENT"] || false;
          const parts = emails[j].payload.parts || [];

          if (userAttachConfig) {
            if (parts.length > 0) {
              console.log('Transfer attachment files to slack target...')
              // task: need improve only do with it when forward rules match
              attachments = getAttachmentsFromPayload(emails[j].payload, emails[j].id, authToken.accessToken, userEmail);
              emailContent.attachments = attachments;
            }
          }

          /** end get attachment file */

          uniqueTargetsUser.forEach(function (target) {
            //console.log('checkmail send target is ' + target, ', and slackToken is ', slackToken);
            forwarded = forwardEmailToSlackfile(emailContent, target, slackToken);
            if (forwarded) {
              console.info(`Email '${emailContent.subject}' successfully forwarded to user '${target}'.`);
            } else {
              console.error(`Failed to forward email '${emailContent.subject}' to user '${target}'.`);
            }
            updateTaskReport(forwarded, userEmail, target, emailContent.subject, workspaceName);

          });
        }
      }


    }
    // Set the lastMailIdKey to the newest email's timestamp
    if (newestMailTimestamp > 0) {
      var keeplastmailtimestamp = Math.floor(newestMailTimestamp / 1000) + 1; // Convert to Unix timestamp in seconds
      scriptProperties.setProperty(lastMailIdKey, keeplastmailtimestamp.toString());
      console.log('Updated lastMailIdKey to: ' + keeplastmailtimestamp);
    }
  }
}

/**
 * Retrieves user-defined rules for a specific workspace.
 * @param {string} userEmail - The user's email address.
 * @param {string} workspaceId - The workspace ID for which to get rules.
 * @returns {Object} - The user-defined rules for the specified workspace.
 */
function getUserRulesForWorkspace(userEmail, workspaceId) {
  var scriptProperties = PropertiesService.getScriptProperties();
  var rulesKey = 'rules_' + userEmail;
  var allRules = JSON.parse(scriptProperties.getProperty(rulesKey) || '{}');
  // get rules from GCS
  //var allRules = getPropertyFromGCS(userEmail, rulesKey);

  return allRules[workspaceId] || {};
}


/**
 * Fetches emails using the provided access token and user email.
 * @param {string} accessToken - The access token.
 * @param {string} userEmail - The email of the user.
 * @return {Array} - An array of Gmail threads or messages.
 */
function fetchEmails(accessToken, userEmail, refreshToken, try_once) {
  var scriptProperties = PropertiesService.getScriptProperties();
  var lastMailIdKey = 'LAST_MAIL_ID_' + userEmail;
  var lastMailId = scriptProperties.getProperty(lastMailIdKey);


  var userConfigKey = 'CONFIG_' + userEmail;
  var userConfig = JSON.parse(scriptProperties.getProperty(userConfigKey));
  //var userConfig = getPropertyFromGCS(userEmail, userConfigKey);

  var userMailConfig = userConfig["GMAIL_CONFIG"];
  var userAttachConfig = userConfig["GMAIL_CONFIG_ATTACHMENT"];


  var checkUnreadOnly = true;

  if (userMailConfig && userMailConfig == 'false') {
    checkUnreadOnly = false;
  };

  var searchQuery = checkUnreadOnly ? 'is:unread' : '';

  if (!lastMailId) {
    var checkStartTimeKey = 'GMAIL_CONFIG_STARTTIME' + userEmail;
    var checkStartTime = scriptProperties.getProperty(checkStartTimeKey);
    if (checkStartTime) {
      var startTime = new Date(checkStartTime);
      startTime.setHours(0, 0, 0, 0); // Set to start of the day
      var startTimeUnix = Math.floor(startTime.getTime() / 1000); // Convert to Unix timestamp in seconds
      searchQuery += ' after:' + startTimeUnix;
    }
  } else {
    // Ensure lastMailId is a Unix timestamp in seconds
    var lastMailIdUnix = parseInt(lastMailId, 10);
    searchQuery += ' after:' + lastMailIdUnix;
  }
  console.log('searchQuery for user ' + userEmail + ': ' + searchQuery);

  // Use the Gmail API to search for emails with the access token
  var url = 'https://www.googleapis.com/gmail/v1/users/' + encodeURIComponent(userEmail) + '/messages?q=' + encodeURIComponent(searchQuery);

  var options = {
    method: 'get',
    headers: {
      'Authorization': 'Bearer ' + accessToken
    },
    muteHttpExceptions: true
  };

  var response = UrlFetchApp.fetch(url, options);
  var result = JSON.parse(response.getContentText());

  //console.log('FetchEmails searchQuery result : ' + JSON.stringify(result));
  if (result.error) {
    console.log('fetchEmails result error code is: ' + result.error.code);
    //console.log('fetchEmails full error object: ', JSON.stringify(result.error));

    // Check if the error is related to invalid credentials
    var errorMessage = JSON.stringify(result.error).toLowerCase();
    if ((errorMessage.includes('invalid credentials') || errorMessage.includes('401')) && try_once < 1) {
      console.log('Invalid credentials detected, attempting to refresh token...');
      // Place the token refresh logic here
      var authToken = refreshGmailAccessToken(refreshToken, userEmail);
      if (authToken) {
        try {
          return emails = fetchEmails(authToken.accessToken, userEmail, authToken.refreshToken, 1);
        } catch (fetchError) {
          console.error('Failed to fetch emails after token refresh: ' + fetchError);
        }
      } else {
        console.error('Failed to refresh token for user: ' + userEmail);
      }
    }
    return [];
  }

  if (result.resultSizeEstimate > 0) {
    var messages = result.messages || [];
    var emailIds = messages.map(function (message) {
      return message.id;
    });
    console.log('Fetch email details emails emailIds : ' + emailIds);

    // Fetch email details
    var emails = emailIds.map(function (id) {
      var emailUrl = 'https://www.googleapis.com/gmail/v1/users/' + encodeURIComponent(userEmail) + '/messages/' + id;
      var emailResponse = UrlFetchApp.fetch(emailUrl, options);
      return JSON.parse(emailResponse.getContentText());
    });

    // issue set mail id when forward is ok?
    //var lastMailTimestamp = parseInt(result.internalDate); // internalDate is in milliseconds
    //var keeplastmailtimestamp = Math.floor(lastMailTimestamp / 1000); // Convert to Unix timestamp in seconds
    //scriptProperties.setProperty(lastMailIdKey, keeplastmailtimestamp.toString());

    //scriptProperties.setProperty(lastMailIdKey, emailIds[emailIds.length - 1]);
    return emails;
  } else
    return [];
}

/**
 * Refreshes the access token using the refresh token.
 * @param {string} refreshToken - The refresh token.
 * @return {Object} - The new access token and refresh token object.
 */
function refreshAccessToken(refreshToken) {
  var tokenUrl = 'https://oauth2.googleapis.com/token';
  var clientId = '611884908205-upntifjr313s67tfp2irn8j2kan1qnc3.apps.googleusercontent.com'; // Gmail Client ID
  var clientSecret = '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'; // Gmail Client Secret

  var payload = {
    'client_id': clientId,
    'client_secret': clientSecret,
    'refresh_token': refreshToken,
    'grant_type': 'refresh_token'
  };

  var options = {
    'method': 'post',
    'contentType': 'application/x-www-form-urlencoded',
    'payload': payload,
    'muteHttpExceptions': true
  };
  console.log('refreshAccessToken mute ' + options);
  var response = UrlFetchApp.fetch(tokenUrl, options);
  var tokenResponse = JSON.parse(response.getContentText());

  console.log('refreshAccessToken tokenResponse ' + tokenResponse);

  if (tokenResponse.error) {
    throw new Error('Failed to refresh access token: ' + tokenResponse.error);
  }

  return {
    accessToken: tokenResponse.access_token,
    refreshToken: refreshToken // Refresh token typically doesn't change
  };
}

/**
 * Retrieves the rules for a specific user from the script properties.
 * @param {string} userEmail - The user's email address.
 * @returns {Object} - An object containing the user's rules, or null if no rules are found.
 */
function getUserRules(userEmail) {
  var scriptProperties = PropertiesService.getScriptProperties();
  var userRulesKey = 'rules_' + userEmail;
  var userRules = JSON.parse(scriptProperties.getProperty(userRulesKey));
  // get rules from GCS
  //var userRules = getPropertyFromGCS(userEmail, rulesKey);
  if (!userRules) {
    console.log('No rules found for user: ' + userEmail);
    return null;
  }

  return userRules;
}

/**
 * Extracts relevant email content, including handling of attachments and checking for "IMPORTANT" label.
 * @param {Object} emailData - The JSON representation of the email.
 * @param {String} userAccessToken - authToken.accessToken
 * @return {Object} - An object containing the extracted email content.
 */
function extractEmailContentFromJson(emailData, userAccessToken, userEmail) {
  const headers = emailData.payload.headers || [];
  const parts = emailData.payload.parts || [];
  const labelIds = emailData.labelIds || [];

  // Helper function to get a specific header
  function getHeader(headers, name) {
    const header = headers.find(header => header.name.toLowerCase() === name.toLowerCase());
    return header ? header.value : '';
  }

  // Extracting necessary headers
  const fromSender = getHeader(headers, 'From');
  const subject = getHeader(headers, 'Subject');
  const emailDate = getHeader(headers, 'Date');
  const toUser = getHeader(headers, 'To');

  // Extracting snippet
  const snippet = emailData.snippet || '';
  console.log('extractEmailContentFromJson: subject is ', subject);

  // Extracting the body content
  let body = getBodyFromPayload(emailData.payload);

  // Handling attachments
  let attachments = [];

  var scriptProperties = PropertiesService.getScriptProperties();
  const userConfigKey = 'CONFIG_' + userEmail;
  var userConfig = JSON.parse(scriptProperties.getProperty(userConfigKey));

  // In your existing code where you construct the initialMessage
  const userTimezone = userConfig["TIMEZONE"] || Session.getScriptTimeZone(); // Fallback to script's timezone if not set
  const formattedDate = formatDateWithTimezone(emailDate, userTimezone);
  //console.log('formattedDate is ', formattedDate, ', and emailDate is ', emailDate, ' , and userTimezone is ', userTimezone);

  // task: need improve check if rules to forward, if yes go on else stop
  /** remove start 
  var userAttachConfig = userConfig["GMAIL_CONFIG_ATTACHMENT"] || false;

  if (userAttachConfig) {
    if (parts.length > 0) {
      console.log('Transfer attachment files to slack ...')
      // task: need improve only do with it when forward rules match
      attachments = getAttachmentsFromPayload(emailData.payload, emailData.id, userAccessToken, userEmail);
    }
  }
  ** remove end */
  // Check if the email is marked as "IMPORTANT"
  const isImportant = labelIds.includes("IMPORTANT");
  const groupSetting = '';  // for future use
  // for test html format
  const htmlBody = 'body' || "No HTML content available";
  const textBody = 'body' || "No text content available";

  return {
    fromSender: fromSender,
    subject: subject,
    date: emailDate,
    formattedDate: formattedDate,
    snippet: snippet,
    body: body,
    attachments: attachments || '',
    isImportant: isImportant,
    group: groupSetting,
    toUser: toUser,
    htmlBody: '',
    textBody: ''
  };
}

/**
 * Helper function to extract the body content from the email payload.
 * @param {Object} payload - The payload object containing email data.
 * @return {string} - The decoded body content of the email.
 */
function getBodyFromPayload(payload) {
  if (!payload) {
    console.log('getBodyFromPayload: payload is undefined or null...');
    return '';
  }

  // Recursive function to process parts
  function getBodyFromParts(parts) {
    for (var i = 0; i < parts.length; i++) {
      const part = parts[i];
      //console.log('getBodyFromParts part.partId = ', part.partId, ' body size = ', part.body.size);

      // Handle multipart types by recursion
      if (part.mimeType.startsWith('multipart/')) {
        const result = getBodyFromParts(part.parts || []);
        //console.log('multipart/ result is ', result);
        if (result) return result;
      }

      // Prioritize 'text/plain'  over  'text/html'
      if (part.mimeType === 'text/plain' && part.body && part.body.data) {
        //console.log('getBodyFromParts: text/plain part.body', part.body.size);
        const result_tp = extractAndDecodeEmailBody(part);
        //console.log('getBodyFromParts: text/plain part.body result ', result_tp);
        return result_tp;
      }

      if (part.mimeType === 'text/html' && part.body && part.body.data) {
        //console.log('getBodyFromParts: text/html part.body ', part.body.size);
        const result_tp = extractAndDecodeEmailBody(part);
        //console.log('getBodyFromParts: text/html part.body result', result_tp.substring(300));
        return result_tp;
      }

    }
    return '';
  }

  // Check if payload is an array and process each element
  if (Array.isArray(payload)) {
    //console.log('getBodyFromPayload: payload is an array.', payload.length);
    return getBodyFromParts(payload);
  }

  // Start processing parts if available
  if (payload.parts) {
    //console.log('getBodyFromPayload: payload.parts found.');
    return getBodyFromParts(payload.parts);
  }

  // Fallback for payload body data if parts are not available
  if (payload.body && payload.body.data) {
    //console.log('getBodyFromPayload: Decoding payload body. header is ', payload.headers);
    //console.log('getBodyFromPayload payload.body.size = ', payload.body.size);
    return extractAndDecodeEmailBody(payload); // issue payload?
  }

  console.log('getBodyFromPayload: No body content found.');
  return ''; // Return empty string if no body content found
}

// Function to decode the body data using Base64URL
function decodeBase64(body) {
  try {
    return Utilities.newBlob(Utilities.base64DecodeWebSafe(body)).getDataAsString();
  } catch (e) {
    console.error('Error decoding Base64 body data: ', e);
    return '';
  }
}

/**
 * Extracts and decodes the email body based on the Content-Transfer-Encoding.
 * @param {Object} part - The email part object containing headers and body.
 * @return {string} - The decoded email body.
 */
function extractAndDecodeEmailBody(part) {
  // Extract the body and headers
  const body = part.body.data || ''; // Ensure body is defined
  const headers = part.headers || []; // Ensure headers are defined
  const mimeType = part.mimeType || 'text/plain'; // Set a default mimeType
  const encodingHeader = headers.find(header => header.name.toLowerCase() === 'content-transfer-encoding');
  const encoding = encodingHeader ? encodingHeader.value.toLowerCase() : null;

  //console.log('Extracting and decoding email body...');
  //console.log('MIME Type:', mimeType);
  //console.log('Encoding:', encoding || 'No encoding found');

  // Heuristic check for base64 encoding (Base64URL or Base64)
  const decodedString = isBase64Encoded(body);

  if (!decodedString) {
    console.log('Body appears to not be Base64 encoded. ');
  } else {
    console.log('Body appears to be Base64 encoded. ');
    return decodedString;
  }


  // Decode the body based on the Content-Transfer-Encoding header
  if (encoding) {
    switch (encoding) {
      case 'base64':
        return decodeBase64(body);
      case 'quoted-printable':
        //console.log('Decoding Quoted-Printable...');
        const decodedQP = decodeQuotedPrintable(body);
        if (mimeType == 'text/plain' || mimeType == 'text/html') {
          console.log('Fallback to Base64 decoding after Quoted-Printable... mimeType = ', mimeType);
          return decodeBase64(decodedQP);
        }

        // Fallback to Base64 if quoted-printable decoding seems incorrect
        if (isBase64Encoded(decodedQP)) {
          console.log('Fallback to Base64 decoding after Quoted-Printable...');
          return decodeBase64(decodedQP);
        }
        return decodedQP;
      //return decodeQuotedPrintable(body);
      case '7bit':
      case '8bit':
      case 'binary':
      case 'utf-8':
        return body; // Body is in plain text or utf-8, no decoding needed
      default:
        console.warn(`Unknown encoding type: ${encoding}. Returning original body.`);
        return body;
    }
  } else {
    // If no encoding is found, return the body as-is
    console.warn('No Content-Transfer-Encoding header found. Returning original body.');
    return body;
  }
}

/**
 * Decodes a quoted-printable encoded string.
 * Handles soft line breaks, special characters, and ensures robustness across different edge cases.
 * @param {string} encodedString - The quoted-printable encoded string.
 * @return {string} - The decoded string.
 */
function decodeQuotedPrintable(encodedString) {
  if (!encodedString) {
    console.log('Input is undefined or null');
    return '';  // Handle cases where the input is undefined or null
  }

  // Step 1: Remove soft line breaks (indicated by '=' at the end of the line)
  let decodedString = encodedString.replace(/=\r?\n/g, '');

  // Step 2: Decode each hexadecimal representation (e.g., "=3D" becomes "=")
  decodedString = decodedString.replace(/=([0-9A-Fa-f]{2})/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  // Step 3: Normalize newline characters
  decodedString = decodedString.replace(/\r\n/g, '\n');  // Normalize CRLF (Windows) to LF (Unix)
  decodedString = decodedString.replace(/\r/g, '\n');    // Normalize CR (old Macs) to LF (Unix)

  // Step 4: Decode HTML entities if the content appears to be HTML
  if (isHtmlContent(decodedString)) {
    console.log('Quoted-printable content appears to be HTML. Decoding HTML entities...');
    decodedString = decodeHtmlEntities(decodedString);
  }

  return decodedString;
}

/**
 * Checks if a string appears to be Base64 or Base64URL encoded.
 * This is a heuristic check based on the content pattern and length.
 * It also tries decoding to ensure the validity.
 * @param {string} str - The string to check.
 * @return {boolean} or - decodedString  if the string looks like Base64 encoded, false otherwise.
 */
function isBase64Encoded(str) {
  // Remove any whitespace characters before checking
  str = str.trim();

  // Base64 and Base64URL patterns
  const base64Pattern = /^[A-Za-z0-9+/]+[=]{0,2}$/; // Regular Base64
  const base64UrlPattern = /^[A-Za-z0-9-_]+[=]{0,2}$/; // Base64URL

  // Check if the string length is a multiple of 4
  const isValidLength = str.length % 4 === 0;

  // Match against Base64 or Base64URL pattern
  const isValidBase64 = base64Pattern.test(str) || base64UrlPattern.test(str);

  // If the pattern matches and the length is correct, proceed to decode
  if (isValidLength && isValidBase64) {
    try {
      // Attempt to decode as Base64; issue decode twice sometime
      const decodedString = Utilities.newBlob(Utilities.base64DecodeWebSafe(str)).getDataAsString();

      // Check if the decoded string is valid by making sure it's not binary garbage
      return decodedString;
    } catch (e) {
      // If decoding fails, return false
      console.warn('Base64 decoding failed, string is not valid Base64:', e);
      return false;
    }
  }

  return false; // Return false if length or pattern does not match
}


/**
 * Checks if the content is HTML based on headers or content.
 * @param {string} content - The content to check.
 * @return {boolean} - True if the content is HTML, false otherwise.
 */
function isHtmlContent(content) {
  return /<html[^>]*>/i.test(content) || /<\/[a-z]+>/i.test(content);
}

/**
 * Decodes HTML entities in a string (e.g., "&amp;" becomes "&").
 * @param {string} htmlString - The HTML encoded string.
 * @return {string} - The decoded string.
 */
function decodeHtmlEntities(htmlString) {
  const doc = DocumentApp.create('tempDoc');
  doc.getBody().setText(htmlString);
  return doc.getBody().getText();
}


/**
 * Helper function to extract attachments from the email payload.
 * @param {Object} payload - The payload object containing email data.
 * @param {string} messageId - The Gmail message ID.
 * @param {string} userAccessToken - The OAuth access token for the user's Gmail account.
 * @param {string} userEmail - The user's email address.
 * @return {Array} - An array of attachment objects containing fileName, mimeType, and URL.
 */
function getAttachmentsFromPayload(payload, messageId, userAccessToken, userEmail) {
  var attachments = [];

  if (payload.parts) {
    for (var i = 0; i < payload.parts.length; i++) {
      var part = payload.parts[i];
      if (part.filename && part.body && part.body.attachmentId) {
        try {
          var attachmentUrl = 'https://www.googleapis.com/gmail/v1/users/' + encodeURIComponent(userEmail) + '/messages/' + messageId + '/attachments/' + part.body.attachmentId;

          var attachmentOptions = {
            headers: {
              'Authorization': 'Bearer ' + userAccessToken
            }
          };

          var attachmentResponse = UrlFetchApp.fetch(attachmentUrl, attachmentOptions);
          var attachmentData = JSON.parse(attachmentResponse.getContentText());

          // Save the attachment to Drive (optional) and generate a public link
          // Decode the attachment data
          var decodedData = Utilities.base64DecodeWebSafe(attachmentData.data);
          // Get the size of the decoded data (in bytes)
          const decodedDataSize = decodedData.length; // Length of the Byte[] array gives the size in bytes

          //console.log("Decoded data size: " + decodedDataSize + " bytes");

          attachments.push({
            decodedData: decodedData,
            fileName: part.filename,
            mimeType: part.mimeType,
            size: decodedDataSize
            //url: file.getUrl() || ''
          });
        } catch (e) {
          console.error('Error fetching attachment: ', e.message);
          continue; // Skip this attachment if there's an error
        }
      }
    }
  }

  return attachments;
}

/**
 * Creates the Slack message block for email content, including an "IMPORTANT" flag if applicable.
 * @param {Object} emailContent - The email content to be formatted for Slack.
 * @return {Object} - An object containing the Slack message blocks.
 */
function createSlackMessage(emailContent) {
  const fileUrl = 'https://gii-network.slack.com/files/U07GDBX59GV/F07H53DPWQY/google_cloud_platform___apis__your_invoice_is_available_for_011738-75712d-cf33ca';

  return {
    blocks: [
      {
        type: "divider" // Divider added after the first section
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*${emailContent.subject}* ${emailContent.isImportant ? '*:exclamation: IMPORTANT*' : ''}\n*From:* ${emailContent.fromSender}\n*Date:* ${emailContent.date}`
        }
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `${emailContent.snippet || 'No preview available.'}\n\nClick *Show More* to view the full content.`
        },
        accessory: {
          type: "button",
          text: {
            type: "plain_text",
            text: "Show More"
          },
          action_id: "expand_message",
          value: JSON.stringify({
            subject: emailContent.subject,
            fullBody: emailContent.body || 'No content available',
            date: emailContent.date,
            fromSender: emailContent.fromSender,
            attachments: emailContent.attachments || []
          })
        }
      },

      {
        type: "context",
        elements: emailContent.attachments.length > 0 ? emailContent.attachments.map(attachment => ({
          type: "mrkdwn",
          text: `<${attachment.url}|${attachment.fileName}>`
        })) : [{
          type: "mrkdwn",
          text: "No attachments."
        }]
      },
      {
        type: "divider" // Divider added after the second section
      }, {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": `View full email: <${fileUrl}|Click here to view the complete email file>`
        }
      },
      {
        type: "divider" // Divider added after the second section
      },
      {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": "<!DOCTYPE html>\n<html>\n<head>\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n  <style>\n    a {\n      text-decoration: underline;\n      color: #ffffff;\n    }\n  </style>\n</head>\n<body>\n<!-- Content here -->\n</body>\n</html>\n```"
        }
      }

    ]
  };
}

/**
 * Deduplicates Slack targets to ensure each email is only forwarded once per target.
 * @param {Array} targets - Array of Slack targets from matched rules.
 * @return {Array} - Array of unique Slack targets.
 */
function deduplicateTargets(targets) {
  var seen = {};
  return targets.filter(function (target) {
    //var key = target.user + '|' + target.channel;
    var key = target;
    if (seen[key]) {
      return false;
    }
    seen[key] = true;
    return true;
  });
}

/**
 * Checks if the given rule applies to the email.
 * @param {Object} rule - The user's forwarding rule.
 * @param {Object} emailContent - The email content to check against the rules.
 * @return {Object|null} - Returns an object with Slack user or channel if the rule applies, otherwise null.
 */
function ruleApplies(rule, emailContent, userEmail) {
  if (!rule || !emailContent) {
    return null; // Ensure both rule and email content are provided
  }

  var scriptProperties = PropertiesService.getScriptProperties();
  var userConfigKey = 'CONFIG_' + userEmail;
  var userConfig = JSON.parse(scriptProperties.getProperty(userConfigKey));
  // get CONFIG from GCS, 
  //var userConfig = getPropertyFromGCS(userEmail, userConfigKey);

  var userTimezone = userConfig["TIMEZONE"];

  if (!userTimezone) {
    console.warn('User timezone not found for user: ' + userEmail + '. Using script timezone by default.');
    userTimezone = Session.getScriptTimeZone(); // Use script's timezone by default
  }
  console.log('userTimezone is ', userTimezone);

  var emailDate = new Date(emailContent.date);

  // task: no need? Convert emailDate to user's timezone
  emailDate = convertToTimezone(emailDate, userTimezone);

  var emailSubject = emailContent.subject ? emailContent.subject.toLowerCase() : '';

  // Default timezone to GMT, change to user's timezone if needed
  //var userTimezone = Session.getScriptTimeZone(); // Retrieve user's timezone setting
  //emailDate = new Date(emailDate.toLocaleString("en-US", { timeZone: userTimezone }));

  // Check time period
  var startTime = rule['Type-timePeriod'] ? parseTime(rule['Type-timePeriod'].startTime) : null;
  var endTime = rule['Type-timePeriod'] ? parseTime(rule['Type-timePeriod'].endTime) : null;

  if (startTime && endTime) {
    var emailHours = emailDate.getHours();
    var emailMinutes = emailDate.getMinutes();
    //console.log('rule startTime ' + startTime.hours + ':' + startTime.minutes + 'and rule endTime ' + endTime.hours + ':' + endTime.minutes);
    //console.log('emailHours = ' + emailHours + ', and emailMinutes = ' + emailMinutes);

    if (
      (emailHours > startTime.hours ||
        (emailHours === startTime.hours && emailMinutes >= startTime.minutes)) &&
      (emailHours < endTime.hours ||
        (emailHours === endTime.hours && emailMinutes <= endTime.minutes))
    ) {
      // Check if the subject includes rule's subject words
      var ruleSubject = rule['Type-subject'] ? rule['Type-subject'].toLowerCase() : '';
      if (emailSubject.includes(ruleSubject)) {
        // Return the Slack target information
        return rule['slackTarget-user'] || null;
      }

      var ruleSender = rule['Type-sender'] ? rule['Type-sender'].toLowerCase() : '';
      var ruleGroup = rule['Type-group'] ? rule['Type-group'].toLowerCase() : '';

      var emailSender = emailContent.fromSender.toLowerCase();
      var emailGroup = emailContent.group ? emailContent.group.toLowerCase() : ''; // Assuming group information is present

      console.log('ruleSender is ', ruleSender, ' , emailSender is ', emailSender);

      // Check if ruleSender exists
      if (ruleSender) {
        // Split ruleSender by any of the following delimiters: ';', ',', '/', or whitespace
        var ruleSenderArray = ruleSender.split(/[;,\/\s]+/).map(function (sender) {
          return sender.trim();  // Trim any extra spaces around senders
        }).filter(Boolean);  // Filter out any empty strings that may result from extra delimiters

        console.log('Parsed ruleSenderArray is:', ruleSenderArray);

        // Check if emailSender is in the list of rule senders
        if (ruleSenderArray.includes(emailSender)) {
          // Return the Slack target information
          return rule['slackTarget-user'] || null;
        }
      }

      // Check if email group matches rule group
      if (ruleGroup && emailGroup == ruleGroup) {
        // Return the Slack target information
        return rule['slackTarget-user'] || null;
      }
    }
  }

  return null; // No match
}

/**
 * Converts a date or time object to the specified timezone.
 * @param {Date|Object} dateOrTime - The date or time object to convert.
 * @param {string} timezone - The target timezone.
 * @return {Date|Object} - The converted date or time object.
 */
function convertToTimezone(dateOrTime, timezone) {
  var validTimezone = convertToValidTimezone(timezone);

  if (dateOrTime instanceof Date) {
    //return new Date(dateOrTime.toLocaleString('en-US', { timeZone: timezone }));

    try {
      return new Date(dateOrTime.toLocaleString('en-US', { timeZone: validTimezone }));
    } catch (e) {
      throw new Error(`Invalid time zone: ${validTimezone}`);
    }
  } else {
    // Assuming dateOrTime is an object with hours and minutes
    var now = new Date();
    var date = new Date(now.getFullYear(), now.getMonth(), now.getDate(), dateOrTime.hours, dateOrTime.minutes);
    var convertedDate = new Date(date.toLocaleString('en-US', { timeZone: validTimezone }));

    return {
      hours: convertedDate.getHours(),
      minutes: convertedDate.getMinutes()
    };
  }
}

function convertToValidTimezone(timezone) {
  // Match timezones in the format GMT±XX:XX
  var gmtMatch = timezone.match(/GMT([+-]\d{2}):(\d{2})/);
  
  if (gmtMatch) {
    // Extract the hour part of the GMT offset
    var hourOffset = parseInt(gmtMatch[1], 10);  // Get the number after GMT (either positive or negative)
    
    // IANA time zones reverse the sign compared to GMT notation
    return `Etc/GMT${hourOffset > 0 ? '-' : '+'}${Math.abs(hourOffset)}`;
  }

  return timezone; // Return original timezone if not in GMT format
}



function _convertToValidTimezone(timezone) {
  // Check if timezone is in GMT+ or GMT- format, and convert it to a valid IANA timezone if necessary.
  if (/GMT[+-]\d{2}:\d{2}/.test(timezone)) {
    // Extract the GMT offset and convert it to IANA time zone 'Etc/GMT+X' or 'Etc/GMT-X'
    var offset = timezone.replace('GMT', '');
    return `Etc/GMT${-parseInt(offset.replace(':', ''), 10) / 100}`; // GMT offset conversion
  }
  return timezone; // Return valid IANA timezone if already in correct format
}


/**
 * Parses a time string in the format "HH:MM" and returns an object with hours and minutes.
 * @param {string} timeStr - The time string to parse.
 * @return {Object} - An object with hours and minutes.
 */
function parseTime(timeStr) {
  if (!timeStr) return null;

  var timeParts = timeStr.split(':');
  return {
    hours: parseInt(timeParts[0], 10),
    minutes: parseInt(timeParts[1], 10)
  };
}


function joinChannel(slackToken, channel) {
  var joinUrl = 'https://slack.com/api/conversations.join';
  var joinOptions = {
    method: 'post',
    contentType: 'application/json',
    headers: {
      'Authorization': 'Bearer ' + slackToken
    },
    payload: JSON.stringify({
      channel: channel
    })
  };

  var joinResponse = UrlFetchApp.fetch(joinUrl, joinOptions);
  var joinResponseJson = JSON.parse(joinResponse.getContentText());

  if (!joinResponseJson.ok) {
    console.error('Failed to join Slack channel: ' + joinResponseJson.error);
    return false;
  }
  return true;
}

/**
 * Forwards the email content to the specified Slack channel or user as a file.
 * @param {Object} emailContent - The email content to be forwarded.
 * @param {string} slackTargetChannels - The Slack target (channel or user) to send the email to.
 * @param {Object} slackToken - The user's Slack OAuth token.
 * @return {boolean} - Returns true if the email was successfully forwarded, false otherwise.
 */
function forwardEmailToSlackfile(emailContent, slackTargetChannels, slackToken) {
  // Log the slackTargetChannels to check its type and value
  console.log("slackTargetChannels value and type:", slackTargetChannels, typeof slackTargetChannels);

  // Ensure that slackTargetChannels is a string before using split
  //if (typeof slackTargetChannels !== 'string') {
  // Convert to string if it's not
  //  slackTargetChannels = String(slackTargetChannels);
  //}

  // Now that slackTargetChannels is a string, we can safely use split
  let channelId = slackTargetChannels;    //.split('_', 1)[0];

  console.log("Extracted channel ID:", channelId);

  // Continue with the rest of your logic

  if (!slackToken || !slackToken.trim()) {
    throw new Error('Missing or invalid Slack access token.');
  }

  // Check if the target is a user ID and convert it to a direct message channel ID
  if (channelId.startsWith('U')) {
    const dmChannelId = getDirectMessageChannelId(slackToken, channelId);
    if (!dmChannelId) {
      console.error('Failed to get direct message channel ID for user:', channelId);
      return false;
    }
    channelId = dmChannelId;
  }

  // Create the email content in .eml format
  const emlContent = createEmlFormat(emailContent);

  // Create a Blob from the .eml content
  const filename = `email_${new Date().toISOString().replace(/[:.]/g, '-')}`; // Use .eml extension?
  const blob = Utilities.newBlob(emlContent, 'message/rfc822', filename);


  // Get the upload URL and file ID
  const uploadInfo = getUploadURL(slackToken, blob.getBytes(), filename);
  if (!uploadInfo) {
    return false;
  }

  // Upload the file to Slack
  const uploadSuccess = uploadFileToSlack(uploadInfo.uploadUrl, blob);
  if (!uploadSuccess) {
    return false;
  }
  // Construct the initial message with detailed email information
  const initialMessage_for_attach = `
\t From: ${emailContent.fromSender}
\t To: ${emailContent.toUser}
\t Subject: ${emailContent.subject}
\t Date: ${emailContent.formattedDate}

${emailContent.snippet || ''}
`.trim(); // Use trim() to remove any leading/trailing whitespace

  // Check if there are attachments
  if (emailContent.attachments && emailContent.attachments.length > 0) {
    // Post a message to the target channel or user
    const initialMessage = `Gmail Forwarded by giiSlacker™:  \n  ${initialMessage_for_attach}`;
    const postMessageResult = postMessageToSlack(slackToken, channelId, initialMessage);

    if (!postMessageResult.success) {
      console.log("Failed to post initial message to Slack.");
      return false;
    }

    const threadTs = postMessageResult.thread_ts; // Get the thread timestamp from the posted message

    // Upload the mail body file as a reply to the posted message
    const bodyUploadSuccess = completeUpload(slackToken, uploadInfo.fileId, channelId, emailContent.subject, threadTs);

    if (!bodyUploadSuccess.success) {
      console.log('Failed to upload mail body as a thread reply.');
      return false;
    }

    // Handle attachments
    const fileIds = []; // Array to store file IDs for completion
    for (let attachment of emailContent.attachments) {
      console.log("Handle attachments ...  ", attachment.fileName);

      // Check attachment size limit (e.g., 20MB)
      const sizeLimit = 20 * 1024 * 1024; // 20MB
      if (attachment.size > sizeLimit) {
        console.warn(`Attachment ${attachment.fileName} exceeds size limit and will not be sent.`);
        continue;
      }

      // Get attachment content
      const attachmentContent = getAttachmentContent(attachment);
      const attachmentUploadInfo = getUploadURL(slackToken, attachmentContent.getBytes(), attachment.fileName);

      if (!attachmentUploadInfo) {
        console.log("Handle attachmentUploadInfo failed ...");
        return false;
      }

      // Upload the attachment file as a reply to the posted message
      const attachmentUploadSuccess = uploadAttachmentFileToSlack(
        attachmentUploadInfo.uploadUrl,
        attachmentContent,
        threadTs, // Use the thread timestamp from the initial message
        channelId,
        slackToken,
        attachmentUploadInfo.fileId
      );

      if (!attachmentUploadSuccess) {
        console.log("uploadAttachmentFileToSlack failed ...");
        return false;
      }

      // Store the file ID for later completion
      fileIds.push({ id: attachmentUploadInfo.fileId, title: attachment.fileName });
      console.log('attachmentUploadInfo.fileId is ', attachmentUploadInfo.fileId);

    }

    // Complete the upload for all attachments in one call
    if (fileIds.length > 0) {
      const attachmentCompleteSuccess = completeUpload(
        slackToken,
        fileIds,
        channelId,
        '', // attachment.fileName
        threadTs
      );
      if (!attachmentCompleteSuccess.success) {
        console.log("completeUpload for attachments failed ...");
        return false;
      }
    }
  } else {
    // If there are no attachments, complete the upload directly
    const result = completeUpload(slackToken, uploadInfo.fileId, channelId, emailContent.subject, 0);

    if (!result.success) {
      console.log('completeUpload failed...');
      return false;
    }
  }

  return true; // Indicate success
}

/**
 * Creates the email content in .eml format.
 * @param {Object} emailContent - The email content object.
 * @return {string} - The formatted email content in .eml format.
 */
function createEmlFormat(emailContent) {
  //MIME-Version: 1.0
  //Content-Type: text/plain; charset=UTF-8
  //Content-Transfer-Encoding: quoted-printable

  // 初始化一个空字符串来构建最终的附件列表
  let attachmentFiles = '';

  // 遍历emailContent.attachments数组
  emailContent.attachments.forEach((attachment, index) => {
    // 假设emailContent是一个包含附件信息的对象
    console.log('createEmlFormat: emailContent.attachments is ', attachment.fileName);

    // 检查是否有url，如果没有则跳过此条目
    if (attachment.url) {
      // 构建超链接
      const link = `<a href="${attachment.url}">${attachment.fileName}</a>`;
      // 将超链接追加到attachmentFiles字符串中，并在每个链接之间加上换行符
      attachmentFiles += link + (index < emailContent.attachments.length - 1 ? '<br>' : '');
    } else {
      // 如果没有url，则添加一条提示信息
      attachmentFiles += ` ${attachment.fileName} `;
    }
  });

  // 最终的attachmentFiles字符串包含了所有附件的超链接
  console.log('Formatted attachment files:', attachmentFiles);

  return `
From: ${emailContent.fromSender}
To: ${emailContent.toUser || 'undisclosed'}
Subject: ${emailContent.subject}
Date: ${emailContent.formattedDate}

${emailContent.body}

${attachmentFiles}
`.trim();
}

/**
 * Decodes the email body if it is encoded in a specific format.
 * @param {string} body - The encoded email body.
 * @return {string} - The decoded email body.
 */
function decodeEmailBody(body) {
  // Assuming the body is in base64 or quoted-printable format
  // You may need to adjust this based on how the body is encoded
  try {
    // If the body is base64 encoded
    const decodedBase64 = Utilities.newBlob(Utilities.base64Decode(body)).getDataAsString('utf-8');
    return decodedBase64;
  } catch (e) {
    console.error("Error decoding email body: " + e.message);
    return body; // Return the original body if decoding fails
  }
}



/**
 * Retrieves the content of an email attachment.
 * @param {Object} attachment - The attachment object.
 * @return {Blob} - The content of the attachment as a Blob.
 */
function getAttachmentContent(attachment) {
  // Decode the base64-encoded content
  const decodedContent = attachment.decodedData;  //Utilities.base64Decode(attachment.content);
  // Create a Blob from the decoded content

  const blob = Utilities.newBlob(decodedContent, attachment.mimeType, attachment.fileName);
  return blob;
}

/**
 * Gets an upload URL for a file from Slack.
 * @param {Object} slackToken - The user's Slack OAuth token.
 * @param {string} fileContent - The content of the file to be uploaded.
 * @return {Object|null} - An object containing the upload URL and file ID if successful, null otherwise.
 */
function getUploadURL(slackToken, fileContent, filename) {
  //const fileLength = fileContent.getBytes().length; // Get the byte length of the Blob
  const fileLength = fileContent.length; // Get the byte length of the Blob
  //const filename = `email_${new Date().toISOString().replace(/[:.]/g, '-')}.eml`; // Use .eml extension

  const url = `https://slack.com/api/files.getUploadURLExternal?filename=${encodeURIComponent(filename)}&length=${fileLength}`;

  const options = {
    method: 'get',
    headers: {
      'Authorization': 'Bearer ' + slackToken,
      'Content-Type': 'application/json; charset=utf-8'
    }
  };

  //console.log('Request URL for getUploadURL:', url);

  try {
    const response = UrlFetchApp.fetch(url, options);
    const result = JSON.parse(response.getContentText());

    //console.log('Response from getUploadURL:', JSON.stringify(result));

    if (result.ok) {
      return { uploadUrl: result.upload_url, fileId: result.file_id };
    } else {
      console.error("Slack API error (getUploadURL): " + result.error);
      return null;
    }
  } catch (e) {
    console.error("Error getting upload URL from Slack: " + e.message);
    return null;
  }
}

/**
 * Uploads a file to Slack using the provided upload URL.
 * @param {string} uploadUrl - The upload URL obtained from Slack.
 * @param {Blob} fileContent - The content of the file to be uploaded as a Blob.
 * @return {boolean} - True if the upload is successful, false otherwise.
 */
function uploadFileToSlack(uploadUrl, fileContent) {
  const boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
  const delimiter = "\r\n--" + boundary + "\r\n";
  const closeDelimiter = "\r\n--" + boundary + "--";

  const contentDisposition = `Content-Disposition: form-data; name="file"; filename="${fileContent.getName()}"\r\n`;
  const contentType = 'Content-Type: message/rfc822\r\n\r\n'; // Set content type for .eml files
  //const contentType = `Content-Type: ${fileContent.getContentType()}\r\n\r\n`;
  //const contentType = `Content-Type: text/html\r\n\r\n`;


  //const payload = delimiter + contentDisposition + contentType + fileContent.getBytes() + closeDelimiter;
  // Convert the Blob to a UTF-8 string and construct the payload
  const payload = delimiter + contentDisposition + contentType + fileContent.getDataAsString() + closeDelimiter;
  //console.log('uploadFileToSlack fileContent:', payload);

  const options = {
    method: 'post',
    contentType: 'multipart/form-data; boundary=' + boundary,
    payload: payload
  };

  try {
    const response = UrlFetchApp.fetch(uploadUrl, options);
    console.log('Response from uploadFileToSlack:', response.getContentText());

    if (response.getResponseCode() === 200) {
      return true;
    } else {
      console.error("Slack API error (uploadFileToSlack): " + response.getContentText());
      return false;
    }
  } catch (e) {
    console.error("Error uploading file to Slack: " + e.message);
    return false;
  }
}
/**
 * Uploads an attachment file to Slack using the provided upload URL.
 * @param {string} uploadUrl - The upload URL obtained from Slack.
 * @param {Blob} fileContent - The content of the file to be uploaded as a Blob.
 * @param {string} threadTs - The thread timestamp to associate the file with the main email thread.
 * @return {boolean} - True if the upload is successful, false otherwise.
 */
function uploadAttachmentFileToSlack(uploadUrl, fileContent, threadTs, channelId, slackToken, fileId) {

  const boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
  const delimiter = "\r\n--" + boundary + "\r\n";
  const closeDelimiter = "\r\n--" + boundary + "--";

  // Prepare the form data for the file
  const contentDisposition = `Content-Disposition: form-data; name="file"; filename="${fileContent.getName()}"\r\n`;
  const contentType = `Content-Type: ${fileContent.getContentType()}\r\n\r\n`;
  //console.log('Content-Type:', contentType);
  // Convert Blob content to bytes (directly use fileContent.getBytes())
  const fileBytes = fileContent.getBytes();
  //const payload = delimiter + contentDisposition + contentType + Utilities.newBlob(fileBytes).getDataAsString() + closeDelimiter;
  // Create the payload using binary data, not a string representation
  const payload = Utilities.newBlob(
    delimiter + contentDisposition + contentType
  ).getBytes()
    .concat(fileBytes)
    .concat(Utilities.newBlob(closeDelimiter).getBytes());


  const options = {
    method: 'post',
    contentType: 'multipart/form-data; boundary=' + boundary,
    payload: payload,
    muteHttpExceptions: true  // Capture full response even on error
  };

  try {
    const response = UrlFetchApp.fetch(uploadUrl, options);
    const statusCode = response.getResponseCode();
    console.log('Response from uploadAttachmentFileToSlack:', response.getContentText(), '; statusCode ', statusCode);

    if (statusCode === 200) {
      // Add the file to the Slack thread using the thread_ts
      if (threadTs) {
        console.log('uploadAttachmentFileToSlack is 200 and threadTs is ', threadTs);

        //const fileId = JSON.parse(response.getContentText()).file.id;
        //const associateFileResponse = associateFileWithThread(fileId, threadTs, channelId,slackToken);
        //return associateFileResponse.ok;
      }
      return true;
    } else {
      console.error(`Slack API error (uploadAttachmentFileToSlack): ${response.getContentText()}`);
      return false;
    }
  } catch (e) {
    console.error(`Error uploading file to Slack: ${e.message}`);
    return false;
  }
}

/**
 * Completes the file upload process by associating the file with the main email thread.
 * @param {string} fileId - The ID of the uploaded file.
 * @param {string} threadTs - The thread timestamp to associate the file with.
 * @return {Object} - The response from Slack API.
 */
function associateFileWithThread(fileId, threadTs, channelId, slackToken) {
  const url = "https://slack.com/api/chat.postMessage";
  const payload = {
    "channel": channelId,
    "text": "Attached file",
    "thread_ts": threadTs, // Ensure this is correctly passed
    "attachments": [{
      "file_id": fileId
    }]
  };

  const options = {
    method: "post",
    contentType: "application/json",
    headers: {
      "Authorization": "Bearer " + slackToken
    },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  const response = UrlFetchApp.fetch(url, options);
  const result = JSON.parse(response.getContentText());

  if (!result.ok) {
    console.error("Error associating file with thread: " + response.getContentText());
  }

  return result;
}


/**
 * Completes the upload of a file to Slack and shares it in the specified channel or thread.
 * @param {Object} slackToken - The user's Slack OAuth token.
 * @param {string} fileId - The file ID obtained from the upload URL.
 * @param {string} channelId - The ID of the channel or direct message where the file should be shared.
 * @param {string} emailSubject - The subject of the email (optional).
 * @param {string} threadTs - The thread timestamp (optional) to attach the file to a specific thread.
 * @return {Object} - Response object including success status and thread_ts (if available).
 */
function completeUpload(slackToken, fileId, channelId, emailSubject, threadTs) {
  const url = 'https://slack.com/api/files.completeUploadExternal';
  const email_Content = emailSubject || 'Email_Content is ...'; // Default to email subject
  var initial_Comment = 'Gmail Forwarded by giiSlacker™';


  // Check if fileId is an array or a single value
  const filesPayload = Array.isArray(fileId)
    ? fileId.map(file => ({ id: file.id, title: file.title })) // Create an array of file objects
    : [{ id: fileId, title: email_Content }]; // Single file case, ensure fileIds is an object
  //console.log('fileId is ', fileId, ' , filePayload is ', filesPayload);

  // Add thread_ts if provided to reply in the same thread
  if (threadTs) {
    console.log('threadTs is ', threadTs);
    initial_Comment = ''; // show blank when send to a thread as reply
  }

  const payload = {
    files: filesPayload,
    channel_id: channelId,
    thread_ts: threadTs,
    initial_comment: initial_Comment,
  };

  const options = {
    method: 'post',
    headers: {
      'Authorization': 'Bearer ' + slackToken,
      'Content-Type': 'application/json; charset=utf-8'
    },
    payload: JSON.stringify(payload)
  };

  try {
    const response = UrlFetchApp.fetch(url, options);
    const result = JSON.parse(response.getContentText());

    //console.log('Response from completeUpload:', JSON.stringify(result));

    if (result.ok) {
      if (!threadTs) {
        var file = result.files[0];
        let newThreadTs = null;

        // Check for 'ts' in public shares
        if (file.shares && file.shares.public) {
          var publicShares = file.shares.public;
          var firstKey = Object.keys(publicShares)[0];
          newThreadTs = publicShares[firstKey][0].ts;
        }

        // Check for 'ts' in private shares if not found in public
        if (!newThreadTs && file.shares && file.shares.private) {
          var privateShares = file.shares.private;
          var firstKey = Object.keys(privateShares)[0];
          newThreadTs = privateShares[firstKey][0].ts;
        }

        //console.log("slack thread ts for attachment is ", newThreadTs);

        return { success: true, thread_ts: newThreadTs };

      } else {
        return { success: true };
      }

    } else {
      console.error("Slack API error (completeUpload): " + result.error);
      return { success: false, error: result.error };
    }
  } catch (e) {
    console.error("Error completing upload to Slack: " + e.message);
    return { success: false, error: e.message };
  }
}


/**
 * Shares a file in a Slack channel or thread using chat.postMessage.
 * @param {Object} slackToken - The user's Slack OAuth token.
 * @param {string} fileId - The file ID to be shared.
 * @param {string} channelId - The channel where the file should be shared.
 * @param {string} threadTs - The thread timestamp (optional) for replying in a thread.
 * @param {string} initialComment - The comment to be added with the file.
 * @return {Object} - Response object including success status and thread_ts.
 */
function shareFileInChannel(slackToken, fileId, channelId, threadTs, initialComment) {
  const url = 'https://slack.com/api/chat.postMessage';
  const payload = {
    channel: channelId,
    text: initialComment + ' shared file',
    attachments: [
      {
        file_id: fileId
      }
    ]
  };

  // Add thread_ts if provided
  if (threadTs) {
    payload.thread_ts = threadTs;
  }

  const options = {
    method: 'post',
    headers: {
      'Authorization': 'Bearer ' + slackToken,
      'Content-Type': 'application/json; charset=utf-8'
    },
    payload: JSON.stringify(payload)
  };

  try {
    const response = UrlFetchApp.fetch(url, options);
    const result = JSON.parse(response.getContentText());

    console.log('Response from shareFileInChannel:', JSON.stringify(result));

    if (result.ok) {
      return { success: true, thread_ts: result.ts };
    } else {
      console.error("Error sharing file in channel: " + result.error);
      return { success: false, error: result.error };
    }
  } catch (e) {
    console.error("Error sharing file in Slack: " + e.message);
    return { success: false, error: e.message };
  }
}


/**
 * Get the direct message channel ID for a user.
 * @param {Object} slackToken - The user's Slack OAuth token.
 * @param {string} userId - The user ID.
 * @return {string|null} - The direct message channel ID or null if not found.
 */
function getDirectMessageChannelId(slackToken, userId) {
  const url = `https://slack.com/api/conversations.open`;
  const payload = {
    users: userId
  };

  const options = {
    method: 'post',
    headers: {
      'Authorization': 'Bearer ' + slackToken,
      'Content-Type': 'application/json; charset=utf-8'
    },
    payload: JSON.stringify(payload)
  };

  try {
    const response = UrlFetchApp.fetch(url, options);
    const result = JSON.parse(response.getContentText());

    if (result.ok && result.channel && result.channel.id) {
      return result.channel.id;
    } else {
      console.error("Slack API error (conversations.open): " + result.error);
      return null;
    }
  } catch (e) {
    console.error("Error opening conversation with user: " + e.message);
    return null;
  }
}

/**
 * Posts a message to a Slack channel or user.
 * @param {Object} slackToken - The user's Slack OAuth token.
 * @param {string} channelId - The ID of the channel or user where the message should be sent.
 * @param {string} message - The message to be sent.
 * @return {Object} - Response object including success status and thread_ts if applicable.
 */
function postMessageToSlack(slackToken, channelId, message) {
  const url = 'https://slack.com/api/chat.postMessage';
  const payload = {
    channel: channelId,
    text: message,
  };

  const options = {
    method: 'post',
    headers: {
      'Authorization': 'Bearer ' + slackToken,
      'Content-Type': 'application/json; charset=utf-8'
    },
    payload: JSON.stringify(payload)
  };

  try {
    const response = UrlFetchApp.fetch(url, options);
    const result = JSON.parse(response.getContentText());

    console.log('Response from postMessageToSlack:', JSON.stringify(result));

    if (result.ok) {
      return { success: true, thread_ts: result.ts }; // Return the thread timestamp
    } else {
      console.error("Slack API error (postMessageToSlack): " + result.error);
      return { success: false };
    }
  } catch (e) {
    console.error("Error posting message to Slack: " + e.message);
    return { success: false };
  }
}

// get all registed user's email
function getGmailTokenKey() {
  // Get all script properties
  var props = PropertiesService.getScriptProperties();
  var allProps = props.getProperties();

  // Initialize an empty object to store matching properties
  var gmailTokenProps = [];

  const prefix = 'GMAIL_AUTH_TOKEN_';

  // Loop through all properties and filter those that match the key pattern 'Gmail_Token_*'
  for (var key in allProps) {
    if (key.startsWith(prefix)) {
      //gmailTokenProps[key] = allProps[key]; // Add the matching property to the result object
      gmailTokenProps.push(key.substring(prefix.length));
    }
  }

  // Log the matching properties
  Logger.log('Matching Gmail Token Properties: ' + JSON.stringify(gmailTokenProps));

  return gmailTokenProps; // Return the matching properties if needed
}

/**
 * Retrieves specified files for a user from GCS and saves their content to script properties.
 * @param {string} userEmail - The email of the user.
 */
function saveGCSDataToScriptProperties(userEmail) {
  var scriptProperties = PropertiesService.getScriptProperties();
  //var bucketName = scriptProperties.getProperty('BUCKET_NAME');

  // Dynamically create file names and property keys based on the user's email
  var fileList = [
    {
      fileName: 'SLACK_AUTH_TOKEN_' + userEmail + '.json',
      propKey: 'SLACK_AUTH_TOKEN_' + userEmail
    },
    {
      fileName: 'CONFIG_' + userEmail + '.json',
      propKey: 'CONFIG_' + userEmail
    },
    {
      fileName: 'rules_' + userEmail + '.json',
      propKey: 'rules_' + userEmail
    }
  ];

  // Get GCS service
  //var gcsService = getGCSService();  // Replace with your method to get GCS access

  // Loop through the file list, retrieve content from GCS, and save to script properties
  fileList.forEach(function (fileInfo) {
    var fileContent = getPropertyFromGCS(userEmail, fileInfo.propKey);
    if (fileContent) {
      scriptProperties.setProperty(fileInfo.propKey, JSON.stringify(fileContent));
      Logger.log('Saved content of ' + fileInfo.fileName + ' to scriptProperties as ' + fileInfo.propKey);
    } else {
      Logger.log('Failed to retrieve content for ' + fileInfo.fileName);
    }
  });
}
/**
 * Updates the task report by recording the email forwarding history to GCS.
 * Each report is stored in a daily file named with workspaceId and the date in 'workspaceId-date.json' format.
 * @param {boolean} forwarded - Indicates if the email was successfully forwarded.
 * @param {string} target - The target user or channel the email was forwarded to.
 * @param {string} subject - The subject of the forwarded email.
 */
function updateTaskReport(forwarded, userEmail,target, subject,workspaceName) {
  var date = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyyMMdd");  // Format the date as 'yyyyMMdd'
  var fileName = 'TaskReport' + '-' + date + '.json';  // Generate the file name in 'workspaceId-date.json' format

  var bucketName = getBucketName();  // Retrieve the GCS bucket name from script properties or other config
  if (!bucketName) {
    console.error('Bucket name is not available.');
    return;
  }

  var folderName = userEmail;  // Use user's email as folder name in GCS
  /**var gcsService = getGCSService();  // Initialize GCS service with the correct OAuth

  if (!gcsService) {
    console.error('Failed to initialize GCS Service.');
    return;
  }*/

  var fileUrl = 'https://storage.googleapis.com/storage/v1/b/' + bucketName + '/o/' + encodeURIComponent(folderName + '/' + fileName) + '?alt=media';

  var options = {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + ScriptApp.getOAuthToken()    //gcsService.getAccessToken()
    }
  };

  var fileContent;
  try {
    var response = UrlFetchApp.fetch(fileUrl, options);
    if (response.getResponseCode() === 200) {
      // Parse existing file content
      fileContent = JSON.parse(response.getContentText());
    } else {
      // If the file doesn't exist, initialize an empty array
      fileContent = [];
    }
  } catch (e) {
    console.log('File not found or other error, initializing new report file: ' + e.message);
    fileContent = [];  // Create a new array if no file exists
  }

  // Add the new report entry
  var reportEntry = {
    forwarded: forwarded,
    target: workspaceName,
    subject: subject,
    timestamp: new Date().toISOString()
  };
  fileContent.push(reportEntry);

  // Save the updated report back to GCS
  var uploadUrl = 'https://storage.googleapis.com/upload/storage/v1/b/' + bucketName + '/o?uploadType=media&name=' + encodeURIComponent(folderName + '/' + fileName);
  var uploadOptions = {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + ScriptApp.getOAuthToken(),    //gcsService.getAccessToken(),
      'Content-Type': 'application/json'
    },
    payload: JSON.stringify(fileContent)
  };

  try {
    var uploadResponse = UrlFetchApp.fetch(uploadUrl, uploadOptions);
    if (uploadResponse.getResponseCode() === 200 || uploadResponse.getResponseCode() === 201) {
      console.log('Task report updated successfully.');
    } else {
      console.error('Failed to update task report: ' + uploadResponse.getResponseCode());
    }
  } catch (e) {
    console.error('Error saving task report to GCS: ' + e.message);
  }
}


/**
 * Helper function to load a file from GCS using OAuth token for authorization.
 * The file is stored in a folder named after the user's email, and the filename is based on the key.
 * @param {string} userEmail - The email of the user, used as the folder name.
 * @param {string} key - The key used as the filename (e.g., rules, config).
 * @returns {Object|null} - The file content as an object, or null if the file doesn't exist.
 */
function loadFileFromGCS(userEmail, key) {
  var bucketName = getBucketName();  // Retrieve bucket name from appsscript.json
  if (!bucketName) {
    console.error('Bucket name is not available.');
    return null;
  }

  var folderName = userEmail;  // Use user's email as folder name
  /**var gcsService = getGCSService();  // Initialize GCS service

  if (!gcsService) {
    console.error('Failed to initialize GCS Service.');
    return null;
  }*/

  // Construct the file URL from folder and key
  var fileName = folderName + '/' + key + '.json';
  var fileUrl = 'https://storage.googleapis.com/storage/v1/b/' + bucketName + '/o/' + encodeURIComponent(fileName) + '?alt=media';

  // Fetch the file from GCS using OAuth authorization
  var options = {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + ScriptApp.getOAuthToken()    //gcsService.getAccessToken()
    }
  };

  try {
    // Fetch the file from GCS
    var response = UrlFetchApp.fetch(fileUrl, options);

    // Check if the file exists (200 OK response)
    if (response.getResponseCode() === 200) {
      var fileContent = response.getContentText();  // Get the content as text
      return JSON.parse(fileContent);  // Parse and return the JSON data
    } else {
      console.error('File not found or cannot be accessed: ' + fileName);
      return null;
    }
  } catch (e) {
    console.error('Error loading file from GCS: ' + e.message);
    return null;
  }
}


/**
 * Helper function to save a file to GCS using OAuth token for authorization.
 * The file is stored in a folder named after the user's email, and the filename is based on the key.
 * @param {string} userEmail - The email of the user, used as the folder name.
 * @param {string} key - The key used as the filename (e.g., rules, config).
 * @param {string|Object} content - The content to be saved in the file (will be stringified if it's an object).
 */
function saveFileToGCS(userEmail, key, content) {
  var bucketName = getBucketName();  // Retrieve bucket name from appsscript.json
  if (!bucketName) {
    console.error('Bucket name is not available.');
    return;
  }

  var folderName = userEmail;  // Use user's email as folder name
  /**var gcsService = getGCSService();  // Initialize GCS service

  if (!gcsService) {
    console.error('Failed to initialize GCS Service.');
    return;
  }*/

  // Prepare the content, ensure it's stringified if it's an object
  if (typeof content !== 'string') {
    content = JSON.stringify(content);
  }

  // Construct the file URL from folder and key
  var fileName = folderName + '/' + key + '.json';
  var fileUrl = 'https://storage.googleapis.com/upload/storage/v1/b/' + bucketName + '/o?uploadType=media&name=' + encodeURIComponent(fileName);

  // Fetch the file from GCS or create a new one
  var options = {
    method: 'POST',  // GCS uses POST for uploading new content or overwriting existing files
    headers: {
      Authorization: 'Bearer ' + ScriptApp.getOAuthToken(),    //gcsService.getAccessToken()
      'Content-Type': 'application/json'
    },
    payload: content
  };

  try {
    // Send the content to GCS (file is either created or overwritten)
    var response = UrlFetchApp.fetch(fileUrl, options);

    // Check the response code to confirm success
    if (response.getResponseCode() === 200 || response.getResponseCode() === 201) {
      console.log(`File '${fileName}' saved successfully to GCS.`);
    } else {
      console.error(`Failed to save file '${fileName}'. Response Code: ` + response.getResponseCode());
    }
  } catch (e) {
    console.error('Error saving file to GCS: ' + e.message);
  }
}


