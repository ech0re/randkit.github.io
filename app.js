(function () {
  'use strict';

  // --- Cryptographic random helpers ---

  function randomBytes(n) {
    var arr = new Uint8Array(n);
    crypto.getRandomValues(arr);
    return arr;
  }

  function randomInt(max) {
    if (max <= 0) return 0;
    var limit = Math.floor(0xFFFFFFFF / max) * max;
    var arr = new Uint32Array(1);
    do {
      crypto.getRandomValues(arr);
    } while (arr[0] >= limit);
    return arr[0] % max;
  }

  function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  // --- BIP39 word list (loaded from bip39.txt) ---

  var WORDS = [];

  function loadWordList() {
    return fetch('bip39.txt')
      .then(function (res) { return res.text(); })
      .then(function (text) {
        WORDS = text.trim().split('\n').map(function (w) { return w.trim(); }).filter(Boolean);
      });
  }

  // --- Generator functions ---

  function generatePassword() {
    var upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var lower = 'abcdefghijklmnopqrstuvwxyz';
    var digits = '0123456789';
    var symbols = '!@#$%^&*_+-=?';
    var all = upper + lower + digits + symbols;
    var result = [];
    result.push(upper[randomInt(upper.length)]);
    result.push(lower[randomInt(lower.length)]);
    result.push(digits[randomInt(digits.length)]);
    result.push(symbols[randomInt(symbols.length)]);
    for (var i = 4; i < 20; i++) {
      result.push(all[randomInt(all.length)]);
    }
    for (var j = result.length - 1; j > 0; j--) {
      var k = randomInt(j + 1);
      var tmp = result[j];
      result[j] = result[k];
      result[k] = tmp;
    }
    return result.join('');
  }

  function generatePassphrase() {
    var parts = [];
    for (var i = 0; i < 5; i++) {
      parts.push(WORDS[randomInt(WORDS.length)]);
    }
    return parts.join('-');
  }

  function generatePIN() {
    var result = '';
    for (var i = 0; i < 6; i++) {
      result += randomInt(10).toString();
    }
    return result;
  }

  function generateTOTP() {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var result = '';
    for (var i = 0; i < 32; i++) {
      result += chars[randomInt(chars.length)];
    }
    return result;
  }

  function generateUUID() {
    var bytes = randomBytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    var hex = bytesToHex(bytes);
    return (
      hex.slice(0, 8) + '-' +
      hex.slice(8, 12) + '-' +
      hex.slice(12, 16) + '-' +
      hex.slice(16, 20) + '-' +
      hex.slice(20)
    );
  }

  function generateULID() {
    var ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    var now = Date.now();
    var time = '';
    var t = now;
    for (var i = 0; i < 10; i++) {
      time = ENCODING[t % 32] + time;
      t = Math.floor(t / 32);
    }
    var rand = '';
    for (var j = 0; j < 16; j++) {
      rand += ENCODING[randomInt(32)];
    }
    return time + rand;
  }

  function generateNanoID() {
    var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
    var result = '';
    for (var i = 0; i < 21; i++) {
      result += alphabet[randomInt(alphabet.length)];
    }
    return result;
  }

  function generateObjectId() {
    return bytesToHex(randomBytes(12));
  }

  function generateGitHash() {
    return bytesToHex(randomBytes(20));
  }

  function generateAPIKey() {
    var bytes = randomBytes(20);
    return 'sk_live_' + bytesToHex(bytes);
  }

  function generateJWT() {
    var algs = ['HS256', 'HS384', 'HS512'];
    var header = btoa(JSON.stringify({
      alg: algs[randomInt(algs.length)],
      typ: 'JWT',
      kid: bytesToHex(randomBytes(8))
    })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    var payload = btoa(JSON.stringify({
      sub: randomInt(1000000).toString(),
      name: 'user_' + randomInt(10000),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    var sigBytes = randomBytes(32);
    var sigBin = '';
    for (var i = 0; i < sigBytes.length; i++) {
      sigBin += String.fromCharCode(sigBytes[i]);
    }
    var sig = btoa(sigBin).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return header + '.' + payload + '.' + sig;
  }

  function generateLicense() {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    var groups = [];
    for (var g = 0; g < 5; g++) {
      var group = '';
      for (var i = 0; i < 5; i++) {
        group += chars[randomInt(chars.length)];
      }
      groups.push(group);
    }
    return groups.join('-');
  }

  function generateHexColor() {
    var bytes = randomBytes(3);
    return '#' + bytesToHex(bytes);
  }

  function generateRGB() {
    var bytes = randomBytes(3);
    return 'rgb(' + bytes[0] + ', ' + bytes[1] + ', ' + bytes[2] + ')';
  }

  function generateHSL() {
    var h = randomInt(360);
    var s = randomInt(61) + 20;
    var l = randomInt(51) + 25;
    return 'hsl(' + h + ', ' + s + '%, ' + l + '%)';
  }

  function generateMAC() {
    var bytes = randomBytes(6);
    var parts = [];
    for (var i = 0; i < 6; i++) {
      parts.push(bytes[i].toString(16).padStart(2, '0').toUpperCase());
    }
    return parts.join(':');
  }

  function generateIPv4() {
    var bytes = randomBytes(4);
    return bytes[0] + '.' + bytes[1] + '.' + bytes[2] + '.' + bytes[3];
  }

  function generateIPv6() {
    var bytes = randomBytes(16);
    var groups = [];
    for (var i = 0; i < 16; i += 2) {
      var val = ((bytes[i] << 8) | bytes[i + 1]).toString(16).padStart(4, '0');
      groups.push(val);
    }
    return groups.join(':');
  }

  function generatePort() {
    return (randomInt(65535 - 1024 + 1) + 1024).toString();
  }

  function generateCIDR() {
    var bytes = randomBytes(4);
    var prefix = [8, 16, 24][randomInt(3)];
    return bytes[0] + '.' + bytes[1] + '.' + bytes[2] + '.0/' + prefix;
  }

  function generateUserAgent() {
    var v = function (min, max) { return randomInt(max - min + 1) + min; };
    var browsers = [
      function () { return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + v(100, 130) + '.0.' + randomInt(9999) + '.' + randomInt(999) + ' Safari/537.36'; },
      function () { return 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_' + v(13, 18) + '_' + v(0, 6) + ') AppleWebKit/605.1.15 (KHTML, like Gecko) Version/' + v(14, 18) + '.' + randomInt(5) + ' Safari/605.1.15'; },
      function () { return 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + v(100, 130) + '.0.' + randomInt(9999) + '.' + randomInt(999) + ' Safari/537.36'; },
      function () { return 'Mozilla/5.0 (X11; Linux x86_64; rv:' + v(100, 130) + '.0) Gecko/20100101 Firefox/' + v(100, 130) + '.0'; },
      function () { return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:' + v(100, 130) + '.0) Gecko/20100101 Firefox/' + v(100, 130) + '.0'; },
      function () { return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + v(100, 130) + '.0.0.0 Safari/537.36 Edg/' + v(100, 130) + '.0.0.0'; },
      function () { return 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + v(100, 130) + '.0.' + randomInt(9999) + ' Safari/537.36 OPR/' + v(85, 115) + '.0.0'; },
      function () { return 'Mozilla/5.0 (iPhone; CPU iPhone OS ' + v(14, 18) + '_' + randomInt(5) + ' like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/' + v(14, 18) + '.' + randomInt(2) + ' Mobile/15E148 Safari/604.1'; },
      function () { return 'Mozilla/5.0 (Linux; Android ' + v(10, 14) + '; SM-' + v(900, 999) + ') AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + v(100, 130) + '.0.' + randomInt(9999) + ' Mobile Safari/537.36'; },
      function () { return 'Mozilla/5.0 (iPad; CPU OS ' + v(14, 18) + '_' + randomInt(5) + ' like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/' + v(14, 18) + ' Mobile/15E148 Safari/604.1'; }
    ];
    return browsers[randomInt(browsers.length)]();
  }

  function generateCreditCard() {
    var digits = [4];
    for (var i = 1; i < 15; i++) {
      digits.push(randomInt(10));
    }
    var sum = 0;
    for (var j = 0; j < 15; j++) {
      var d = digits[14 - j];
      if (j % 2 === 0) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
    }
    digits.push((10 - (sum % 10)) % 10);
    var str = digits.join('');
    return str.slice(0, 4) + ' ' + str.slice(4, 8) + ' ' + str.slice(8, 12) + ' ' + str.slice(12);
  }

  function mod97(numericStr) {
    var remainder = 0;
    for (var i = 0; i < numericStr.length; i++) {
      remainder = (remainder * 10 + parseInt(numericStr[i], 10)) % 97;
    }
    return remainder;
  }

  function generateIBAN() {
    var countries = [
      { code: 'FR', len: 27 },
      { code: 'DE', len: 22 },
      { code: 'GB', len: 22 },
      { code: 'ES', len: 24 },
      { code: 'IT', len: 27 }
    ];
    var c = countries[randomInt(countries.length)];
    var bban = '';
    for (var i = 0; i < c.len - 4; i++) {
      bban += randomInt(10).toString();
    }
    var rearranged = bban + c.code + '00';
    var numericStr = '';
    for (var j = 0; j < rearranged.length; j++) {
      var ch = rearranged[j];
      numericStr += /[A-Z]/.test(ch) ? (ch.charCodeAt(0) - 55).toString() : ch;
    }
    var check = (98 - mod97(numericStr)).toString().padStart(2, '0');
    var iban = c.code + check + bban;
    var result = '';
    for (var k = 0; k < iban.length; k += 4) {
      result += (k > 0 ? ' ' : '') + iban.slice(k, k + 4);
    }
    return result;
  }

  function generatePhone() {
    var v = function (min, max) { return randomInt(max - min + 1) + min; };
    var formats = [
      function () { return '+1 (' + v(200, 999) + ') ' + v(200, 999) + '-' + v(1000, 9999); },
      function () { return '+44 ' + v(100, 999) + ' ' + v(1000, 9999) + ' ' + v(1000, 9999); },
      function () { return '+33 ' + v(1, 9) + ' ' + v(10, 99) + ' ' + v(10, 99) + ' ' + v(10, 99) + ' ' + v(10, 99); },
      function () { return '+49 ' + v(100, 999) + ' ' + v(10000000, 99999999); },
      function () { return '+34 ' + v(600, 799) + ' ' + v(100000, 999999); },
      function () { return '+39 ' + v(300, 399) + ' ' + v(1000000, 9999999); },
      function () { return '+61 ' + v(400, 499) + ' ' + v(100000, 999999); },
      function () { return '+81 ' + v(10, 99) + '-' + v(1000, 9999) + '-' + v(1000, 9999); },
      function () { return '+86 ' + v(130, 199) + ' ' + v(1000, 9999) + ' ' + v(1000, 9999); },
      function () { return '+55 ' + v(11, 99) + ' ' + v(90000, 99999) + '-' + v(1000, 9999); },
      function () { return '+7 ' + v(900, 999) + ' ' + v(100, 999) + '-' + v(10, 99) + '-' + v(10, 99); },
      function () { return '+31 ' + v(6, 9) + v(1000000, 9999999); },
      function () { return '+41 ' + v(70, 79) + ' ' + v(1000000, 9999999); },
      function () { return '+32 ' + v(400, 499) + ' ' + v(100000, 999999); },
      function () { return '+48 ' + v(500, 799) + ' ' + v(100000, 999999); }
    ];
    return formats[randomInt(formats.length)]();
  }

  function generateEmail() {
    var locals = 'abcdefghijklmnopqrstuvwxyz0123456789';
    var len = randomInt(7) + 6;
    var local = '';
    for (var i = 0; i < len; i++) local += locals[randomInt(locals.length)];
    var tlds = ['com', 'net', 'org', 'io', 'dev', 'co', 'biz', 'info', 'app', 'xyz', 'tech', 'me', 'tv'];
    var domainLen = randomInt(6) + 4;
    var domain = '';
    for (var j = 0; j < domainLen; j++) domain += locals[randomInt(locals.length)];
    return local + '@' + domain + '.' + tlds[randomInt(tlds.length)];
  }

  function generateAddress() {
    var parts1 = ['Oak', 'Maple', 'Cedar', 'Park', 'River', 'Lake', 'Hill', 'Elm', 'Pine', 'North', 'South', 'East', 'West', 'Green', 'Blue', 'Red', 'Spring', 'Stone', 'Mill', 'Valley', 'Forest', 'Bay', 'Rock', 'Sky', 'Sun', 'Moon', 'Star', 'Fair', 'Bright', 'Cold', 'Warm', 'Long', 'Short', 'New', 'Old', 'Grand', 'High', 'Low', 'Deep', 'Clear', 'Wild', 'Still', 'Swift', 'Bold', 'Calm', 'Dark', 'Main', 'Church', 'Market', 'State', 'Union', 'Central', 'Washington', 'Lincoln', 'Franklin', 'Madison', 'Jefferson', 'King', 'Queen', 'Prince', 'Royal', 'Garden', 'Orchard', 'Meadow', 'Brook', 'Creek', 'Ridge', 'View', 'Gate', 'Bridge', 'Lane', 'Port', 'Harbor', 'Cove'];
    var parts2 = ['view', 'dale', 'hurst', 'wood', 'field', 'land', 'port', 'side', 'ton', 'ville', 'burg', 'ford', 'worth', 'brook', 'crest', 'ridge', 'mont', 'vale', 'haven', 'shire', 'gate', 'way', 'path', 'run', 'point', 'park', 'lake', 'hill', 'spring', 'well', 'stone', 'grove', 'acre', 'court', 'place', 'lane', 'street', 'road', 'drive', 'circle', 'plaza', 'square', 'heights', 'manor', 'estates', 'gardens', 'terrace', 'trail'];
    var streetName = parts1[randomInt(parts1.length)] + parts2[randomInt(parts2.length)];
    var types = ['St', 'Ave', 'Blvd', 'Rd', 'Dr', 'Ln', 'Way', 'Pl', 'Ct', 'Pkwy', 'Hwy', 'rue', 'avenue', 'boulevard', 'chemin', 'str'];
    var cities = ['Paris', 'Lyon', 'Marseille', 'Toulouse', 'Berlin', 'Munich', 'Hamburg', 'London', 'Manchester', 'Birmingham', 'Madrid', 'Barcelona', 'Valencia', 'New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix', 'Toronto', 'Montreal', 'Vancouver', 'Brussels', 'Amsterdam', 'Rome', 'Milan', 'Zurich', 'Vienna', 'Prague', 'Warsaw', 'Stockholm', 'Oslo', 'Copenhagen', 'Dublin', 'Lisbon', 'Athens', 'Budapest', 'Bucharest', 'Sofia', 'Belgrade', 'Zagreb', 'Helsinki', 'Reykjavik', 'Sydney', 'Melbourne', 'Tokyo', 'Seoul', 'Singapore'];
    var countries = ['France', 'Germany', 'United Kingdom', 'Spain', 'United States', 'Canada', 'Belgium', 'Netherlands', 'Italy', 'Switzerland', 'Austria', 'Portugal', 'Poland', 'Sweden', 'Norway', 'Denmark', 'Ireland', 'Greece', 'Czech Republic', 'Hungary', 'Romania', 'Croatia', 'Finland', 'Iceland', 'Australia', 'Japan'];
    var num = (randomInt(99998) + 1).toString();
    var streetType = types[randomInt(types.length)];
    var city = cities[randomInt(cities.length)];
    var country = countries[randomInt(countries.length)];
    var zip;
    if (country === 'France') {
      zip = (randomInt(90000) + 10000).toString();
    } else if (country === 'United States') {
      zip = (randomInt(90000) + 10000).toString();
      if (randomInt(2) === 0) zip += '-' + (randomInt(9000) + 1000);
    } else if (country === 'United Kingdom') {
      var ukLetters = 'ABCDEFGHIJKLMNOPRSTUWYZ';
      zip = ukLetters[randomInt(ukLetters.length)] + ukLetters[randomInt(ukLetters.length)] + (randomInt(9) + 1) + ' ' + (randomInt(9) + 1) + ukLetters[randomInt(ukLetters.length)] + ukLetters[randomInt(ukLetters.length)];
    } else if (country === 'Germany') {
      zip = (randomInt(90000) + 10000).toString();
    } else if (country === 'Canada') {
      var caLetters = 'ABCDEFGHJKLMNPRSTVWXYZ';
      zip = caLetters[randomInt(caLetters.length)] + randomInt(10) + caLetters[randomInt(caLetters.length)] + ' ' + randomInt(10) + caLetters[randomInt(caLetters.length)] + randomInt(10);
    } else {
      zip = (randomInt(90000) + 10000).toString();
    }
    return num + ' ' + streetName + ' ' + streetType + ', ' + zip + ' ' + city + ', ' + country;
  }

  function generateUsername() {
    var charset = 'abcdefghijklmnopqrstuvwxyz0123456789_';
    if (WORDS.length > 0) {
      return WORDS[randomInt(WORDS.length)] + '_' + WORDS[randomInt(WORDS.length)] + randomInt(9999);
    }
    var len = randomInt(6) + 8;
    var s = charset[randomInt(26)];
    for (var i = 1; i < len; i++) s += charset[randomInt(charset.length)];
    return s;
  }

  function generateSlug() {
    if (WORDS.length === 0) return 'random-url-slug';
    var parts = [];
    var len = randomInt(3) + 3;
    for (var i = 0; i < len; i++) {
      parts.push(WORDS[randomInt(WORDS.length)]);
    }
    return parts.join('-');
  }

  function generateLorem() {
    var words = WORDS.length > 0 ? WORDS : [
      'lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit', 'sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore', 'et', 'dolore', 'magna', 'aliqua', 'enim', 'ad', 'minim', 'veniam', 'quis', 'nostrud', 'exercitation', 'ullamco', 'laboris', 'nisi', 'aliquip', 'ex', 'ea', 'commodo', 'consequat', 'duis', 'aute', 'irure', 'in', 'reprehenderit', 'voluptate', 'velit', 'esse', 'cillum', 'fugiat', 'nulla', 'pariatur', 'excepteur', 'sint', 'occaecat', 'cupidatat', 'non', 'proident', 'sunt', 'culpa', 'qui', 'officia', 'deserunt', 'mollit', 'anim', 'id', 'est', 'laborum'
    ];
    var len = randomInt(15) + 10;
    var result = [];
    for (var i = 0; i < len; i++) {
      result.push(words[randomInt(words.length)]);
    }
    var sentence = result.join(' ');
    return sentence.charAt(0).toUpperCase() + sentence.slice(1) + '.';
  }

  function generateCoords() {
    var lat = (randomInt(18000001) - 9000000) / 100000;
    var lng = (randomInt(36000001) - 18000000) / 100000;
    return lat.toFixed(5) + ', ' + lng.toFixed(5);
  }

  function generateNumber() {
    return randomInt(1000001).toLocaleString();
  }

  function generateDate() {
    var start = new Date(2000, 0, 1).getTime();
    var end = new Date(2030, 11, 31).getTime();
    var range = end - start;
    var bytes = randomBytes(6);
    var value = 0;
    for (var i = 0; i < 6; i++) {
      value = value * 256 + bytes[i];
    }
    var timestamp = start + (value % range);
    return new Date(timestamp).toISOString().split('T')[0];
  }

  function generateTimestamp() {
    var now = Math.floor(Date.now() / 1000);
    var offset = randomInt(63072000) - 31536000;
    return (now + offset).toString();
  }

  function generateCron() {
    var minute = randomInt(3) === 0 ? '*' : randomInt(60).toString();
    var hour = randomInt(3) === 0 ? '*' : randomInt(24).toString();
    var dom = randomInt(3) === 0 ? '*' : (randomInt(28) + 1).toString();
    var month = randomInt(3) === 0 ? '*' : (randomInt(12) + 1).toString();
    var dow = randomInt(3) === 0 ? '*' : randomInt(7).toString();
    return minute + ' ' + hour + ' ' + dom + ' ' + month + ' ' + dow;
  }

  function generateBase64() {
    var bytes = randomBytes(32);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function generateHex() {
    return bytesToHex(randomBytes(32));
  }

  function generateBTC() {
    var base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    var result = '1';
    var len = randomInt(9) + 26;
    for (var i = 1; i < len; i++) {
      result += base58[randomInt(base58.length)];
    }
    return result;
  }

  function generateETH() {
    return '0x' + bytesToHex(randomBytes(20));
  }

  function generateRegex() {
    var n = function (min, max) { return randomInt(max - min + 1) + min; };
    var patterns = [
      '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
      '^\\+?[1-9]\\d{1,14}$',
      '^#?([a-fA-F0-9]{6}|[a-fA-F0-9]{3})$',
      '^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,' + n(12, 24) + '}$',
      '^(https?:\\/\\/)?[\\w.-]+\\.[a-z]{2,}(\\/\\S*)?$',
      '^\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$',
      '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
      '^([01]?\\d\\d?|2[0-4]\\d|25[0-5])(\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])){3}$',
      '^[a-zA-Z][a-zA-Z0-9_]{' + n(2, 10) + '}$',
      '^\\d{' + n(4, 12) + '}$',
      '^[a-z0-9-]{' + n(3, 20) + '}$',
      '^[A-Z]{2}\\d{2}[A-Z0-9]{' + n(10, 25) + '}$',
      '^[\\w-.]+@[\\w-]+\\.[a-z]{2,' + n(2, 6) + '}$',
      '^[a-zA-Z\\s]{' + n(2, 30) + '}$',
      '^[0-9a-fA-F]{' + n(16, 64) + '}$',
      '^(0x)?[0-9a-fA-F]{' + n(40, 64) + '}$',
      '^[1-9]\\d{0,' + n(5, 9) + '}$',
      '^[a-zA-Z0-9+/]{' + n(20, 50) + '}=*$',
      '^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$',
      '^[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}$',
      '^\\+[1-9]\\d{0,3}\\s?\\d{1,14}$',
      '^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{' + n(8, 20) + '}$',
      '^[a-z]+(-[a-z]+)*$',
      '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}',
      '^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$',
      '^0x[0-9a-fA-F]{' + n(40, 42) + '}$',
      '^\\[\\d+(,\\d+)*\\]$',
      '^\\d{1,2}/\\d{1,2}/\\d{2,4}$',
      '^(\\d{1,2}:)?(\\d{1,2}:)?\\d{1,2}$',
      '^[A-Z]{2}\\d{2}[A-Z0-9]{4,30}$',
      '^[\\u0020-\\u007E]{' + n(1, 50) + '}$',
      '^\\d{3}-\\d{3}-\\d{4}$',
      '^[a-zA-Z0-9_-]{' + n(8, 32) + '}$',
      '^[\\d\\s+-()]{10,20}$',
      '^[^@]+@[^@]+\\.[a-z]{2,}$',
      '^(https?|ftp)://[^\\s/$.?#].[^\\s]*$',
      '^[a-zA-Z]\\w*$',
      '^\\d{1,5}$',
      '^-?\\d{1,10}(\\.\\d{1,6})?$',
      '^[01]+$',
      '^(true|false)$',
      '^[^\\s]{' + n(1, 256) + '}$',
      '^[\\x20-\\x7E]{' + n(8, 128) + '}$'
    ];
    return patterns[randomInt(patterns.length)];
  }

  function generateHash() {
    return bytesToHex(randomBytes(32));
  }

  function generateFlaskSecret() {
    return bytesToHex(randomBytes(32));
  }

  function generateDjangoSecret() {
    var chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)';
    var result = '';
    for (var i = 0; i < 50; i++) {
      result += chars[randomInt(chars.length)];
    }
    return result;
  }

  function generateNonce() {
    return bytesToHex(randomBytes(16));
  }

  function generateOAuthState() {
    return bytesToHex(randomBytes(24));
  }

  function generateSlugId() {
    var alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    var result = '';
    for (var i = 0; i < 12; i++) {
      result += alphabet[randomInt(alphabet.length)];
    }
    return result;
  }

  // --- Card definitions ---

  var CATEGORIES = [
    { id: 'secrets', label: 'Secrets' },
    { id: 'ids', label: 'IDs' },
    { id: 'colors', label: 'Colors' },
    { id: 'network', label: 'Network' },
    { id: 'testdata', label: 'Test Data' },
    { id: 'text', label: 'Text' },
    { id: 'numbers', label: 'Numbers' },
    { id: 'development', label: 'Development' },
    { id: 'crypto', label: 'Crypto' }
  ];

  var CARDS = [
    { id: 'password', label: 'Password', category: 'secrets' },
    { id: 'passphrase', label: 'Passphrase', category: 'secrets' },
    { id: 'pin', label: 'PIN Code', category: 'secrets' },
    { id: 'totp', label: 'TOTP Secret', category: 'secrets' },
    { id: 'apikey', label: 'API Key', category: 'secrets' },
    { id: 'jwt', label: 'JWT Token', category: 'secrets' },
    { id: 'license', label: 'License Key', category: 'secrets' },
    { id: 'flasksecret', label: 'Flask Secret Key', category: 'secrets' },
    { id: 'djangosecret', label: 'Django Secret Key', category: 'secrets' },
    { id: 'nonce', label: 'CSP Nonce', category: 'secrets' },
    { id: 'oauthstate', label: 'OAuth State', category: 'secrets' },
    { id: 'uuid', label: 'UUID v4', category: 'ids' },
    { id: 'ulid', label: 'ULID', category: 'ids' },
    { id: 'nanoid', label: 'NanoID', category: 'ids' },
    { id: 'objectid', label: 'MongoDB ObjectId', category: 'ids' },
    { id: 'githash', label: 'Git Commit Hash', category: 'ids' },
    { id: 'slugid', label: 'Short Slug ID', category: 'ids' },
    { id: 'hexcolor', label: 'Hex Color', category: 'colors', swatch: true },
    { id: 'rgb', label: 'RGB Color', category: 'colors', swatch: true },
    { id: 'hsl', label: 'HSL Color', category: 'colors', swatch: true },
    { id: 'mac', label: 'MAC Address', category: 'network' },
    { id: 'ipv4', label: 'IPv4 Address', category: 'network' },
    { id: 'ipv6', label: 'IPv6 Address', category: 'network' },
    { id: 'port', label: 'Port Number', category: 'network' },
    { id: 'cidr', label: 'CIDR Block', category: 'network' },
    { id: 'useragent', label: 'User Agent', category: 'testdata' },
    { id: 'creditcard', label: 'Credit Card', category: 'testdata' },
    { id: 'iban', label: 'IBAN', category: 'testdata' },
    { id: 'phone', label: 'Phone Number', category: 'testdata' },
    { id: 'email', label: 'Email Address', category: 'testdata' },
    { id: 'address', label: 'Address', category: 'testdata' },
    { id: 'username', label: 'Username', category: 'testdata' },
    { id: 'slug', label: 'URL Slug', category: 'text' },
    { id: 'lorem', label: 'Lorem Ipsum', category: 'text' },
    { id: 'regex', label: 'Regex Pattern', category: 'text' },
    { id: 'coords', label: 'GPS Coordinates', category: 'numbers' },
    { id: 'number', label: 'Random Number', category: 'numbers' },
    { id: 'date', label: 'Random Date', category: 'numbers' },
    { id: 'timestamp', label: 'Unix Timestamp', category: 'numbers' },
    { id: 'cron', label: 'CRON Expression', category: 'development' },
    { id: 'hash', label: 'SHA-256 Hash', category: 'development' },
    { id: 'base64', label: 'Base64 String', category: 'development' },
    { id: 'hex', label: 'Hex String', category: 'development' },
    { id: 'btc', label: 'Bitcoin Address', category: 'crypto' },
    { id: 'eth', label: 'Ethereum Address', category: 'crypto' }
  ];

  // --- Generator registry ---

  var generators = {
    password: generatePassword,
    passphrase: generatePassphrase,
    pin: generatePIN,
    totp: generateTOTP,
    uuid: generateUUID,
    ulid: generateULID,
    nanoid: generateNanoID,
    objectid: generateObjectId,
    githash: generateGitHash,
    apikey: generateAPIKey,
    jwt: generateJWT,
    license: generateLicense,
    hexcolor: generateHexColor,
    rgb: generateRGB,
    hsl: generateHSL,
    mac: generateMAC,
    ipv4: generateIPv4,
    ipv6: generateIPv6,
    port: generatePort,
    cidr: generateCIDR,
    useragent: generateUserAgent,
    creditcard: generateCreditCard,
    iban: generateIBAN,
    phone: generatePhone,
    email: generateEmail,
    address: generateAddress,
    username: generateUsername,
    slug: generateSlug,
    lorem: generateLorem,
    coords: generateCoords,
    number: generateNumber,
    date: generateDate,
    timestamp: generateTimestamp,
    cron: generateCron,
    regex: generateRegex,
    hash: generateHash,
    flasksecret: generateFlaskSecret,
    djangosecret: generateDjangoSecret,
    nonce: generateNonce,
    oauthstate: generateOAuthState,
    slugid: generateSlugId,
    base64: generateBase64,
    hex: generateHex,
    btc: generateBTC,
    eth: generateETH
  };

  // --- SVG icons ---

  var ICON_COPY = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';

  var ICON_REGEN = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<polyline points="23 4 23 10 17 10"></polyline>' +
    '<path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>';

  // --- Build cards ---

  function buildCards() {
    var main = document.getElementById('main');
    main.innerHTML = '';

    for (var c = 0; c < CATEGORIES.length; c++) {
      var cat = CATEGORIES[c];
      var cardsInCat = CARDS.filter(function (d) { return d.category === cat.id; });
      if (cardsInCat.length === 0) continue;

      var section = document.createElement('section');
      section.className = 'category-section';
      section.setAttribute('data-category', cat.id);

      var heading = document.createElement('h2');
      heading.className = 'category-heading';
      heading.textContent = cat.label;
      section.appendChild(heading);

      var grid = document.createElement('div');
      grid.className = 'grid';

      for (var i = 0; i < cardsInCat.length; i++) {
        var def = cardsInCat[i];
        var card = document.createElement('div');
        card.className = 'card';
        card.setAttribute('data-generator', def.id);
        card.setAttribute('data-label', def.label.toLowerCase());

        var valueHTML = def.swatch
          ? '<div class="card-value-row"><span class="color-swatch"></span><span class="card-value"></span></div>'
          : '<div class="card-value"></div>';

        card.innerHTML =
          '<div class="card-header">' +
            '<span class="card-label">' + def.label + '</span>' +
            '<div class="card-actions">' +
              '<button class="btn-icon btn-copy" title="Copy" aria-label="Copy to clipboard">' +
                ICON_COPY +
                '<span class="copied-tooltip">Copied!</span>' +
              '</button>' +
              '<button class="btn-icon btn-regen" title="Regenerate" aria-label="Regenerate">' +
                ICON_REGEN +
              '</button>' +
            '</div>' +
          '</div>' +
          valueHTML;

        grid.appendChild(card);
      }

      section.appendChild(grid);
      main.appendChild(section);
    }
  }

  function filterCards(query) {
    var q = (query || '').trim().toLowerCase();
    var sections = document.querySelectorAll('.category-section');
    for (var i = 0; i < sections.length; i++) {
      var section = sections[i];
      var cards = section.querySelectorAll('.card');
      var visibleCount = 0;
      for (var j = 0; j < cards.length; j++) {
        var card = cards[j];
        var match = !q || card.getAttribute('data-label').indexOf(q) !== -1;
        card.style.display = match ? '' : 'none';
        if (match) visibleCount++;
      }
      section.style.display = visibleCount > 0 ? '' : 'none';
    }
  }

  // --- DOM logic ---

  function regenerate(card) {
    var type = card.getAttribute('data-generator');
    var gen = generators[type];
    if (!gen) return;

    var value = gen();
    var valueEl = card.querySelector('.card-value');
    valueEl.textContent = value;

    if (type === 'hexcolor' || type === 'rgb' || type === 'hsl') {
      var swatch = card.querySelector('.color-swatch');
      if (swatch) swatch.style.backgroundColor = value;
    }

    valueEl.classList.remove('flash');
    void valueEl.offsetWidth;
    valueEl.classList.add('flash');
  }

  function regenerateAll() {
    var cards = document.querySelectorAll('.card');
    for (var i = 0; i < cards.length; i++) {
      regenerate(cards[i]);
    }
  }

  function copyValue(card) {
    var valueEl = card.querySelector('.card-value');
    var text = valueEl.textContent;
    navigator.clipboard.writeText(text).then(function () {
      var btn = card.querySelector('.btn-copy');
      btn.classList.add('copied');
      setTimeout(function () {
        btn.classList.remove('copied');
      }, 1200);
    });
  }

  // --- Init ---

  document.addEventListener('DOMContentLoaded', function () {
    buildCards();

    loadWordList().then(function () {
      regenerateAll();
    });

    document.getElementById('main').addEventListener('click', function (e) {
      var copyBtn = e.target.closest('.btn-copy');
      if (copyBtn) {
        copyValue(copyBtn.closest('.card'));
        return;
      }
      var regenBtn = e.target.closest('.btn-regen');
      if (regenBtn) {
        regenerate(regenBtn.closest('.card'));
        return;
      }
    });

    document.getElementById('search').addEventListener('input', function () {
      filterCards(this.value);
    });

    document.getElementById('regen-all').addEventListener('click', regenerateAll);

    (function initTheme() {
      var stored = localStorage.getItem('randkit-theme');
      var preferDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      var dark = stored === 'dark' || (stored !== 'light' && preferDark);
      document.documentElement.classList.toggle('dark', dark);
      document.getElementById('theme-toggle').setAttribute('aria-pressed', dark);
    })();

    document.getElementById('theme-toggle').addEventListener('click', function () {
      var dark = document.documentElement.classList.toggle('dark');
      localStorage.setItem('randkit-theme', dark ? 'dark' : 'light');
      this.setAttribute('aria-pressed', dark);
    });
  });
})();
