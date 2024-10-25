/**
 * 初始化脚本属性的初始值。
 */
function initValueOfProperties() {
  var scriptProps = PropertiesService.getScriptProperties();

  // 设置常量
  const BUCKET_NAME = "giislacker_basic_config";
  const GMAIL_CLIENT_ID = "611884908205-upntifjr313s67tfp2irn8j2kan1qnc3.apps.googleusercontent.com";
  const GMAIL_SECRET_KEY = "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";
  const GMAIL_REDIRECT_URI = "https://script.google.com/macros/s/AKfycbzCIlvbyH80k3ghy9Z6t9suFXFc8qXIw0yQJylDNIvJbinOtYSHQdigXgDw1pyK1B2J/exec";

  // 设置脚本属性
  scriptProps.setProperty('BUCKET_NAME', BUCKET_NAME);
  scriptProps.setProperty('GMAIL_CLIENT_ID', GMAIL_CLIENT_ID);
  scriptProps.setProperty('GMAIL_SECRET_KEY', GMAIL_SECRET_KEY);
  scriptProps.setProperty('GMAIL_REDIRECT_URI', GMAIL_REDIRECT_URI);

  // 可选：记录设置的属性值
  Logger.log('Initialized properties: ');
}