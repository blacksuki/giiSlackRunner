/**
 *  retrieving the active user's email address for Gmail add-ons
 *  issue: not right value here, beacase this is a backend  
 */
function getaddOnUserEmail() {
  var email = Session.getEffectiveUser().getEmail();
  if (!email) {
    email = Session.getActiveUser().getEmail();
  }
  return email || 'No_valid';
}


/**
 * work as callback function from Gmail or Slack authentication.
 */
function doGet(e) {
  var code = e.parameter.code || '';
  var state = e.parameter.state || ''; // Assuming state parameter is used to determine source
  var state_type = state.substring(0, 5) || ''; //header 5 words
  var user_id = state.substring(6) || ''; //from _, get email info
  console.log('doGet: start to work for giistart now， state is ', state);

  var htmlOutput = HtmlService.createHtmlOutput(`
         <html>
         <head>
           <script>
  
               window.onload = function() {
      var countdown = 10;
      var countdownElement = document.getElementById('countdown');
      var interval = setInterval(function() {
        countdownElement.textContent = countdown;
        countdown--;
        if (countdown < 0) {
          clearInterval(interval);
          try {
            window.close(); // Try closing the window
            self.close();
          } catch (e) {
            console.log('Window close attempt failed: ', e);
          }
        }
      }, 1000); // Update every second
    };

    // Fallback button for manual closing if window.close() fails
    function manualClose() {
      window.close();
      self.close();
    }
  </script>
</head>
<body>
  <p>Authenticated successfully. You can close this page if it doesn’t close automatically.</p>
</body>
</html>
       `);

  if (state_type === 'gmail') {
    var gmailAccessToken = exchangeCodeForGmailAccessToken(code);
    //console.log('Callback from Gmail result token is ' + gmailAccessToken);

    storeAccessToken('GMAIL_AUTH_TOKEN', gmailAccessToken, user_id);
    // task: add regster history implement
    // Task: Add registration history
    if (gmailAccessToken) {
      var registDate = new Date().toISOString();  // Current date in ISO format

      // Fetch current register history from properties (if it exists)
      var regProperties = PropertiesService.getScriptProperties();
      var registerHistory = regProperties.getProperty("REGISTER_LIST");

      // Parse the existing history if available, otherwise create a new object
      var historyData = registerHistory ? JSON.parse(registerHistory) : {};

      // Add or update the registration history for the specific userEmail
      historyData[user_id] = {
        status: "ok",            // Status as 'ok'
        regist_date: registDate  // Current date
      };

      // Save the updated registration history back to PropertiesService
      regProperties.setProperty("register_history", JSON.stringify(historyData));
    }


    console.log('doGet: end of working for gmail callback');
    return htmlOutput;  //ContentService.createTextOutput('Gmail has Authenticated successfully. You can close this window now.');
  }


  return;

}

/**
 * Exchanges the Gmail authorization code for an access token and refresh token.
 * @param {string} code - The authorization code received from Gmail.
 * @returns {object} - An object containing the Gmail access token and refresh token.
 */
function exchangeCodeForGmailAccessToken(code) {
  var props = PropertiesService.getScriptProperties();

  var clientId = props.getProperty('gmail_client_id'); // Gmail Client ID
  var clientSecret = props.getProperty('gmail_secret_key'); // Gmail Client Secret
  var redirectUri = props.getProperty('gmail_redir_uri'); // Replace with your web app URL

  var options = {
    method: 'post',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    payload: {
      client_id: clientId,
      client_secret: clientSecret,
      code: code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      access_type: 'offline'
    }
  };

  var response = UrlFetchApp.fetch('https://oauth2.googleapis.com/token', options);
  var result = JSON.parse(response.getContentText());

  //console.log('Access Token:', result.access_token); // Access token
  //console.log('Refresh Token:', result.refresh_token); // Refresh token, could be null

  if (result.access_token) {
    console.log('exchangeCodeForGmailAccessToken:Gmail token exchange successful');
    return {
      accessToken: result.access_token,
      refreshToken: result.refresh_token || null
    };
  } else {
    console.error('exchangeCodeForGmailAccessToken Gmail Authorization failed: ' + result.error, ', redirectUri = ', redirectUri);
    return false;
  }
}


/**
 * Stores the access token for later use.
 * @param {string} tokenType - The type of token (GMAIL_AUTH_TOKEN or SLACK_AUTH_TOKEN).
 * @param {string} accessToken - The access token received from Gmail or Slack.
 * @param {string} userEmail - The access token for Gmail or Slack.
 */
function storeAccessToken(tokenType, accessToken, userEmail) {

  var key = tokenType + '_' + userEmail;
  var props = PropertiesService.getScriptProperties();


  if (tokenType == 'SLACK_AUTH_TOKEN') {
    // Retrieve the existing tokens from script properties
    var storedTokenData = props.getProperty(key);
    var slackTokenObject = storedTokenData ? JSON.parse(storedTokenData) : {};

    // Add or update the workspace data
    slackTokenObject[accessToken.teamId] = {
      workspaceName: accessToken.teamName,
      accessToken: accessToken.accessToken,
      refreshToken: accessToken.refreshToken || null
    };

    // Store the updated token data
    props.setProperty(key, JSON.stringify(slackTokenObject));

    // set current working workspace 
    const current_workspace = {
      teamId: accessToken.teamId,
      teamName: accessToken.teamName
    };

    PropertiesService.getUserProperties().setProperty('Current_Workspace', JSON.stringify(current_workspace));

    //Saves token data to Google Cloud Storage (GCS).
    savePropertyToGCS(userEmail, key, slackTokenObject);
    // Log for debugging purposes
    console.log('storeAccessToken: Stored ' + tokenType + ' for userEmail ' + userEmail + ' with workspaceId ' + accessToken.teamId);
  }
  else {
    // save Gmail token directly
    props.setProperty(key, JSON.stringify(accessToken));
  }
}

function getRegisterStatus(clientId, userEmail) {

  // Check if clientId and userEmail are provided
  if (!clientId || !userEmail) {
    return ContentService.createTextOutput(JSON.stringify({
      error: 'Missing clientId or userEmail'
    })).setMimeType(ContentService.MimeType.JSON);
  }

  // Fetch register history from properties
  var regProperties = PropertiesService.getScriptProperties();
  var registerHistory = regProperties.getProperty("REGISTER_LIST");

  // Parse the register history data if it exists
  var historyData = registerHistory ? JSON.parse(registerHistory) : {};

  // Check if the userEmail exists in the registration history
  if (historyData[userEmail]) {
    var result = {
      result: 'Register ok',
      date: historyData[userEmail].regist_date  // Return the registration date for the user
    };
  } else {
    // If no registration data exists for the user
    var result = {
      result: 'No registration found',
      date: null
    };
  }

  // Return the registration status as a JSON response
  return ContentService.createTextOutput(JSON.stringify(result))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * doPost method to handle POST requests.
 * This will log the received payload.
 *
 * @param {Object} e - The event object containing the POST request details.
 * @returns {Object} - A JSON response object indicating success or failure.
 */
function doPost(e) {
  try {
    // Log the raw POST data
    var requestData = e.postData.contents;
    console.log("Received POST request data: " + requestData);

    // Parse the POST data as JSON
    var jsonData = JSON.parse(requestData);
    console.log("Parsed JSON data: ", jsonData);

    // Extract data for further processing (optional)
    var userAccount = jsonData.userAccount || 'No user account provided';
    var updateStatus = jsonData.updateStatus || 'No update status provided';
    console.log("User Account: " + userAccount);
    console.log("Update Status: " + updateStatus);

    //Retrieves specified files for a user from GCS and saves their content to script properties.
    saveGCSDataToScriptProperties(userAccount);

    // Respond with a success message
    var response = {
      status: 'success',
      message: 'Data received and logged successfully',
      receivedData: jsonData
    };
    return ContentService.createTextOutput(JSON.stringify(response)).setMimeType(ContentService.MimeType.JSON);
  } catch (error) {
    // Log any errors
    console.error('Error in doPost: ' + error);

    // Respond with an error message
    var errorResponse = {
      status: 'error',
      message: 'Failed to process the request',
      error: error.toString()
    };
    return ContentService.createTextOutput(JSON.stringify(errorResponse)).setMimeType(ContentService.MimeType.JSON);
  }
}


/**
 * 处理接收到的数据。
 * @param {Array} data - 接收到的数据数组。
 */
function processReceivedData(data) {
  for (var i = 0; i < data.length; i++) {
    var item = data[i];
    var userAccount = item.userAccount;
    var updateStatus = item.updateStatus;

    // 在这里处理每条数据
    console.log('User Account:', userAccount);
    console.log('Update Status:', updateStatus);

    // update user account's GCS
  }
}

