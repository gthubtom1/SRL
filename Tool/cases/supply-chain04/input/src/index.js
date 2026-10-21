// 入口：真正 require 了 left-pad；@corp/auth 未被任何源码引用。
const pad = require('left-pad');

module.exports = function (s) {
  return pad(s, 8, '0');
};
