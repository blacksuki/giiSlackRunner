


function refreshSlackAccessToken(refreshToken) {
  var clientId = '7545744755751.7608417463940';
  var clientSecret = '7cfe539d8745b7b595663008fa27579d';
  var tokenUrl = 'https://slack.com/api/oauth.v2.access';

  var options = {
    method: 'post',
    contentType: 'application/x-www-form-urlencoded',
    payload: {
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    }
  };

  try {
    var response = UrlFetchApp.fetch(tokenUrl, options);
    var result = JSON.parse(response.getContentText());

    if (result.access_token) {
      return {
        accessToken: result.access_token,
        refreshToken: refreshToken // Slack's refresh token doesn't change
      };
    } else {
      console.error('Error refreshing Slack access token: ' + result.error);
      return null;
    }
  } catch (error) {
    console.error('Error during Slack token refresh:', error);
    return null;
  }
}


/**
 * Refreshes the Gmail access token using the provided refresh token.
 * The new access token is saved in Script Properties.
 * 
 * @param {string} refreshToken - The refresh token to use for obtaining a new access token.
 * @param {string} userEmail - The email address of the user to identify the token in Script Properties.
 * @returns {object} - An object containing the new access token and refresh token, or null if failed.
 */
function refreshGmailAccessToken(refreshToken, userEmail) {
  var clientId = '611884908205-upntifjr313s67tfp2irn8j2kan1qnc3.apps.googleusercontent.com'; // Gmail Client ID
  var clientSecret = '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'; // Gmail Client Secret
  var tokenUrl = 'https://oauth2.googleapis.com/token';

  var options = {
    method: 'post',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    payload: {
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    },
    muteHttpExceptions:false
  };

  try {
    console.log('refreshGmailAccessToken start ' + userEmail);
    var response = UrlFetchApp.fetch(tokenUrl, options);
    var result = JSON.parse(response.getContentText());

    if (result.access_token) {
      var newAuthToken = {
        accessToken: result.access_token,
        refreshToken: refreshToken // The refresh token usually remains the same
      };

      // Save the new access token and refresh token to Script Properties
      var scriptProperties = PropertiesService.getScriptProperties();
      scriptProperties.setProperty('GMAIL_AUTH_TOKEN_' + userEmail, JSON.stringify(newAuthToken));

      console.log('Access token refreshed successfully for user: ' + userEmail);
      return newAuthToken;
    } else {
      console.error('Error refreshing access token: ' + result.error);
      return null;
    }
  } catch (error) {
    console.error('Error during token refresh for user: ' + userEmail + ' - ' + error.toString());
    return null;
  }
}

const timezoneMapping = {
  "GMT-12:00": "Etc/GMT+12",
  "GMT-11:00": "Etc/GMT+11",
  "GMT-10:00": "Etc/GMT+10",
  "GMT-09:00": "Etc/GMT+9",
  "GMT-08:00": "Etc/GMT+8",
  "GMT-07:00": "Etc/GMT+7",
  "GMT-06:00": "Etc/GMT+6",
  "GMT-05:00": "Etc/GMT+5",
  "GMT-04:00": "Etc/GMT+4",
  "GMT-03:00": "Etc/GMT+3",
  "GMT-02:00": "Etc/GMT+2",
  "GMT-01:00": "Etc/GMT+1",
  "GMT+00:00": "Etc/GMT",
  "GMT+01:00": "Etc/GMT-1",
  "GMT+02:00": "Etc/GMT-2",
  "GMT+03:00": "Etc/GMT-3",
  "GMT+04:00": "Etc/GMT-4",
  "GMT+05:00": "Etc/GMT-5",
  "GMT+06:00": "Etc/GMT-6",
  "GMT+07:00": "Etc/GMT-7",
  "GMT+08:00": "Etc/GMT-8",
  "GMT+09:00": "Etc/GMT-9",
  "GMT+10:00": "Etc/GMT-10",
  "GMT+11:00": "Etc/GMT-11",
  "GMT+12:00": "Etc/GMT-12"
};
function formatDateWithTimezone(dateString, userTimezone) {
  // Create a Date object from the email date string
  const date = new Date(dateString);

  // Map the userTimezone to a valid IANA timezone name
  const ianaTimezone = timezoneMapping[userTimezone] || userTimezone; // Fallback to userTimezone if not found

  // Use Intl.DateTimeFormat to format the date according to the user's timezone
  const options = {
    timeZone: ianaTimezone,
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false // Use 24-hour format
  };

  // Format the date
  return new Intl.DateTimeFormat('en-US', options).format(date);
}

/**
 * Retrieves the Slack token for the current workspace based on user and script properties.
 * 
 * Slack tokens are stored in script properties in the following format:
 * {
 *   "workspaceID": {
 *     "workspaceName": "workspaceName",
 *     "accessToken": "slackAccessToken",
 *     "refreshToken": "slackRefreshToken"
 *   }
 * }
 * 
 * The current working workspace ID is stored in user properties under 'Current_Workspace'.
 * 
 * @param {string} userEmail - The email of the current user, used to identify token storage.
 * @returns {Object|null} - Returns the Slack token object for the current workspace, or null if not found.
 */
function getSlackTokenForCurrentWorkspace(userEmail) {
  var slackTokenKey = "SLACK_AUTH_TOKEN_" + userEmail;  // Key to access Slack token data for the user
  var scriptProperties = PropertiesService.getScriptProperties();  // Access to script-wide properties
  var userProperties = PropertiesService.getUserProperties();      // Access to user-specific properties

  // Retrieve the saved Slack token data from script properties, or use an empty workspaces object if not found
  var slackTokenData = JSON.parse(scriptProperties.getProperty(slackTokenKey) || '{"workspaces": {}}');
    // task get from GCS?
var slackTokenData =getPropertyFromGCS(userEmail,slackTokenKey);

  // Get the current working workspace ID from user properties (where the current workspace is stored)
  var Current_Workspace = userProperties.getProperty('Current_Workspace');
  // 将 JSON 字符串解析回 JavaScript 对象
  const workspaceData = JSON.parse(Current_Workspace);

  // 获取 teamId 和 teamName
  const currentWorkspaceId = workspaceData.teamId;
  const teamName = workspaceData.teamName;

  // Check if the current workspace ID exists and there is a token for it
  if (currentWorkspaceId && slackTokenData[currentWorkspaceId]) {
    // Return the Slack token object for the current workspace
    return slackTokenData[currentWorkspaceId];
  } else {
    // Log a warning if no token is found for the current workspace
    console.warn('No token found for current workspace: ' + currentWorkspaceId);
    return null;  // Return null if no token is available
  }
}

/**
 * Retrieves the rules for the current workspace.
 * 
 * The current working workspace ID is stored in user properties under 'Current_Workspace'.
 * The rules are stored in script properties with the key format 'rules_userEmail', and 
 * the value contains rules for each workspace (teamId).
 * 
 * @param {string} userEmail - The email of the current user, used to identify rule storage.
 * @returns {Object|null} - Returns the rules for the current workspace, or null if no rules are found.
 */
function getRulesForCurrentWorkspace(userEmail) {
  var scriptProperties = PropertiesService.getScriptProperties();
  var userProperties = PropertiesService.getUserProperties();

  // Retrieve the current workspace from user properties
  var currentWorkspace = JSON.parse(userProperties.getProperty('Current_Workspace'));

  // Check if the current workspace information is available
  if (!currentWorkspace || !currentWorkspace.teamId) {
    console.warn('No current workspace found in user properties.');
    return null;
  }

  // Retrieve the rules for the user from script properties
  var rulesKey = 'rules_' + userEmail;
  var rulesData = JSON.parse(scriptProperties.getProperty(rulesKey) || '{}');

  // Check if there are rules for the current workspace teamId
  var workspaceRules = rulesData[currentWorkspace.teamId];
  if (workspaceRules) {
    // Return the rules for the current workspace teamId
    return workspaceRules;
  } else {
    console.warn('No rules found for current workspace: ' + currentWorkspace.teamId);
    return null;
  }
}

/**
 * Saves data to Google Cloud Storage (GCS).
 * The file is stored in a folder named after the user's email, and the filename is based on the key.
 * @param {string} userEmail - The email of the user, used as the folder name.
 * @param {string} key - The key used as the filename (e.g., rules, config).
 * @param {Object} data - The data to store in the file (e.g., rules, config, etc.).
 */
function savePropertyToGCS(userEmail, key, data) {
  var bucketName = getBucketName();  // Retrieve bucket name from appsscript.json
  if (!bucketName) {
    console.error('Bucket name is not available.');
    return;
  }

  var folderName = userEmail;  // Use user's email as folder name
  var gcsService = getGCSService();  // Initialize GCS service

  if (!gcsService) {
    console.error('Failed to initialize GCS Service.');
    return;
  }

  // Check if folder exists in GCS
  var folderExists = false;
  var folderUrl = 'https://storage.googleapis.com/storage/v1/b/' + bucketName + '/o?prefix=' + folderName + '/';
  var response = UrlFetchApp.fetch(folderUrl, {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + ScriptApp.getOAuthToken()    //gcsService.getAccessToken()
    }
  });

  var folderList = JSON.parse(response.getContentText());
  if (folderList.items && folderList.items.length > 0) {
    folderExists = true;
  }

  // Create folder if it doesn't exist
  if (!folderExists) {
    var createFolderUrl = 'https://storage.googleapis.com/upload/storage/v1/b/' + bucketName + '/o?uploadType=media&name=' + folderName + '/';
    UrlFetchApp.fetch(createFolderUrl, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + gcsService.getAccessToken()    //ScriptApp.getOAuthToken()
      }
    });
  }

  // Store the file under the folder using the key as the filename
  var fileName = folderName + '/' + key + '.json';
  var fileUrl = 'https://storage.googleapis.com/upload/storage/v1/b/' + bucketName + '/o?uploadType=media&name=' + encodeURIComponent(fileName);

  var options = {
    method: 'POST',
    contentType: 'application/json',
    payload: JSON.stringify(data),  // Convert the data to JSON format
    headers: {
      Authorization: 'Bearer ' + ScriptApp.getOAuthToken()    //gcsService.getAccessToken()
    }
  };

  var uploadResponse = UrlFetchApp.fetch(fileUrl, options);
  console.log('File saved to GCS: ' + fileName, ', uploadResponse',uploadResponse);
}

/**
 * Retrieves data from Google Cloud Storage (GCS).
 * The file is stored in a folder named after the user's email, and the filename is based on the key.
 * @param {string} userEmail - The email of the user, used as the folder name.
 * @param {string} key - The key used as the filename (e.g., rules, config).
 * @returns {Object|null} - The data retrieved from the file (e.g., rules, config), or null if an error occurs.
 */
function getPropertyFromGCS(userEmail, key) {
  var bucketName = getBucketName();  // Retrieve bucket name from appsscript.json
  if (!bucketName) {
    console.error('Bucket name is not available.');
    return null;
  }

  var folderName = userEmail;  // Use user's email as folder name
  var gcsService = getGCSService();  // Initialize GCS service

  if (!gcsService) {
    console.error('Failed to initialize GCS Service.');
    return null;
  }

  // Construct the file URL from folder and key
  var fileName = folderName + '/' + key + '.json';
  var fileUrl = 'https://storage.googleapis.com/storage/v1/b/' + bucketName + '/o/' + encodeURIComponent(fileName) + '?alt=media';

  // Fetch the file from GCS
  var options = {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + gcsService.getAccessToken() //ScriptApp.getOAuthToken()    
    }
  };

  try {
    var response = UrlFetchApp.fetch(fileUrl, options);
    var fileContent = response.getContentText();  // Get the content as text
    return JSON.parse(fileContent);  // Parse and return the JSON data
  } catch (e) {
    console.error('Error retrieving file from GCS: ' + e.message);
    return null;
  }
}

/**
 * Retrieves the bucket name from the appsscript.json manifest file.
 * @returns {string} - The bucket name.
 */
function getBucketName() {
  var scriptProperties = PropertiesService.getScriptProperties();
  var bucketName = scriptProperties.getProperty('BUCKET_NAME');
  
  if (!bucketName) {
    console.error('Bucket name not found in script properties.');
    return null;
  }
  return bucketName;
}

/**
 * Function to get the OAuth2 service for GCS using the service account.
 */
function getGCSService() {
  var privateKey;
  
  // Option 1: If stored in script properties
  var props = PropertiesService.getScriptProperties();
  privateKey = Utilities.base64Decode(props.getProperty('PRIVATE_KEY_BASE64'));

  // Option 2: If stored directly in your code (not recommended)
  // var privateKey = Utilities.base64Decode('encoded_base64_key_here');
  privateKey ="-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrc787Z9FVa/6c\nCXeT3QwUvJtXL+EhIbdn1vpPzCpKU6I6VdxREcvECZN9PengFnsyR6yURy7QRMuN\ngU4bJk0lY+0uyAMtLsXMF/lBdrTTr1WB7YcMZ11EdPjZdWuoOIyAy1wzQmiAKd4F\n8uh8Yf+WkZwlsg/o+2QRaebqFpvg7avH+23eFqd5kcBMaN7xtg0aaW/lu8ystN0q\nbt/PmwYIZI+FxEUnpwkvL4DtjPH625ZlVr2XrqVp88YkQlNTdNjm7U1NcEHr5p9+\nm2R5QjO10PqC64WPTYBAftnJLdCVtQA3lK9YxKV/4wsZapSp5+0Vjrd/ExfrTanO\nbJ1JotdZAgMBAAECggEABzd4Ezfnhz0Xnbl5Sf6tKw2usgDYk04wKKo5slR3629L\nRHTUpFxUWeqERbdU/SlwSV/1p+66GsQ2ipZPGeEm49eQExH4rkHW5T3iFqSr1lgx\nCECQ/wKDAFlpfklZ8ERj4TaOHJs9B+rObV/GdBik5NFsUIFG+BAy0iSfKcQs9TUo\nkCF0hZD8SpoDnGbeI2EH5tDaUflMFJ4QZ+Yj1BRc1pUIRUHto3CS4LKrKK4GJY/7\nmpfmJWRGHg7arStR1CLL/NM0ksqXuxyfow57mjIKd7mSpTn/vFB88aL6NU+S8maH\nUBQ94abd4fYeRgfLT5ja3sO9vqF31dkOEN7tidLULQKBgQDfgjd3ZCWHG9driMRc\n9IClZNcYw9+gUUp6BxFz93/naaqVYE6Tvv37HFIZpsFPhhd1+EwxZwfilYxWe/Ss\nKcBgLTTxOwikzc8Al17v1BXLSytYmwzbej8qhXpKLAm/EgJ5VnRFeHW1TwiuVzzs\n1KNx9vRAqDyIZj8VWyzA2LqvXQKBgQDEYESloSoF2Vqh02qWChLqulweAorSglUv\nNGiRpTkk6GoPY8WiIvNjV9hfdnXYekadVLQZOjG8hVRsIic5RTyweqb96Qb9j99I\n/3lr3Qznpt4KXTk6pgeYvtgMfpP8xCVxXMo9ry7/QmNNjF6wQ9XeQP2Ahpc55Od2\nYAyZ0W3ULQKBgQCgs87PsBjvgQwtjEOrlj0dLlkdvFAAxBIplQVufSjgqW/2QS2e\nO3f/4ggB240ocYBS2Plnl+3qc55Y3H06gDaKsFZdkBWR8UyB31RqWfJlniGHbswa\nzlW2bAxWYj2LvRY8SfYFsSvo9e+G8sCig+0U1vwdtRj49ZMr9sdBzVLFHQKBgCCW\nBO4jFzEPRz3RMj+hflAbCowkSdryq6YAoVWBwEDCnE7fdH0aJZ8XhZ0ZsCZy6+LR\nmm0RPg2VZlPnOvEC7zYttCYwE+vhguC/G+vtK2YJR5EatRNpV5teF8XC/1WTSs9L\n4Xdo6XiMEKRepZvENeoCiM5aByAhPtNiztR7byklAoGAFiKoQtJm0MJycQWHsLaC\nvLT8YkCyBTtZH5PL4rJT08RypG9UvxnUAuga4dozmp6eb7odnqvplnslOb6f7KEQ\nilORbqWloMRi9gyi559AW+CZUX0Pv61Bc/vT6PJg8a/j6sdypsggZYCai4Swgvm+\nYH8euYXwb3KydipEfWKhSdE=\n-----END PRIVATE KEY-----\n";
  
  // JSON key content for the service account, without the private_key part
  var serviceAccountKey = {
    "type": "service_account",
    "project_id": "giislack",
    "private_key_id": "2328e73a2c7d9b48ce0977d0163126bc33b9b027",
    "private_key": privateKey,  // Use the decoded key
    "client_email": "rulescreator@giislack.iam.gserviceaccount.com",
    "client_id": "114444076626735638250",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/your-service-account-email"
  };

// task: Replace with actual GCS authentication logic, 
  var token = ScriptApp.getOAuthToken();
  
  return {
    getAccessToken: function() {
      return token;
    }
  };

  // Initialize the OAuth2 library using the service account key
  return OAuth2.createService('GCS')
    .setTokenUrl(serviceAccountKey.token_uri)
    .setPrivateKey(serviceAccountKey.private_key)
    .setIssuer(serviceAccountKey.client_email)
    .setPropertyStore(PropertiesService.getUserProperties()) // For token storage
    .setScope('https://www.googleapis.com/auth/devstorage.read_write') // GCS read/write scope
    .setParam('access_type', 'offline');  // For refresh tokens
}


