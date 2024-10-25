/*
view all properites
**/
function viewUserProperties() {
  var props = PropertiesService.getUserProperties(); // 或者使用 getScriptProperties() 根据需求
  var allProps = props.getProperties();

  // 打印所有属性
  Logger.log(allProps);
}

/*
view all scripts properites
**/
function viewScriptProperties() {
  var props = PropertiesService.getScriptProperties(); // 或者使用 getScriptProperties() 根据需求
  var allProps = props.getProperties();

  // 打印所有属性
  Logger.log(allProps);
}

/*
clear properites of gmail and slack token
**/
function clearAllProperties() {
  // 清除用户属性
  clearUserProperty();

  // 清除应用程序属性
  clearAppProperties();
}

function clearUserProperty() {
  var userProperties = PropertiesService.getUserProperties();
  var allKeys = Object.keys(userProperties.getProperties());

  for (var i = 0; i < allKeys.length; i++) {
    userProperties.deleteProperty(allKeys[i]);
  }
  Logger.log('User properties cleared.');
}

/**
 * 清除所有应用程序属性。
 */
function clearAppProperties() {
  var scriptProperties = PropertiesService.getScriptProperties();
  var allKeys = Object.keys(scriptProperties.getProperties());

  for (var i = 0; i < allKeys.length; i++) {
    scriptProperties.deleteProperty(allKeys[i]);
  }

  Logger.log('Application properties cleared.');
}

/**
 * 删除指定的用户属性。
 * @param {string} propertyName - 属性名称。
 */
function deleteUserProperty(propertyName) {
  var userProperties = PropertiesService.getUserProperties();
  userProperties.deleteProperty(propertyName);

  Logger.log('User property "' + propertyName + '" deleted.');
}

/**
 * 删除指定的应用程序属性。
 * @param {string} propertyName - 属性名称。
 */
function deleteAppProperty(propertyName) {
  var scriptProperties = PropertiesService.getScriptProperties();
  scriptProperties.deleteProperty(propertyName);

  Logger.log('Application property "' + propertyName + '" deleted.');
}


// 删除应用程序属性
function delete_LAST_MAIL_ID_lighterwild() {
  deleteAppProperty('LAST_MAIL_ID_lighterwild@gmail.com');
}



/**
 * Set the bucket name .
 * @returns {string} - true/false.
 */
function setBucketName() {
  var scriptProperties = PropertiesService.getScriptProperties();
  var setbucketName = scriptProperties.setProperty('BUCKET_NAME', 'giislacker_basic_config');

  if (!setbucketName) {
    console.error('Bucket name set in script properties failed.');
    return null;
  }
  console.log('Setting bucket name sucessfully. ', setbucketName);
  return setbucketName;
}

/**
 * test service account
 * 
 */
function testServiceAcc() {
  var userEmail = 'lighterwild@gmail.com';
  //Retrieves specified files for a user from GCS and saves their content to script properties.
  saveGCSDataToScriptProperties(userEmail);

}