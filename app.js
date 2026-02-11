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
    var browsers = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + (randomInt(30) + 100) + '.0.' + randomInt(9999) + '.' + randomInt(999) + ' Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_' + (randomInt(6) + 13) + '_' + randomInt(8) + ') AppleWebKit/605.1.15 (KHTML, like Gecko) Version/' + (randomInt(5) + 14) + '.' + randomInt(5) + ' Safari/605.1.15',
      'Mozilla/5.0 (X11; Linux x86_64; rv:' + (randomInt(30) + 100) + '.0) Gecko/20100101 Firefox/' + (randomInt(30) + 100) + '.0',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:' + (randomInt(30) + 100) + '.0) Gecko/20100101 Firefox/' + (randomInt(30) + 100) + '.0'
    ];
    return browsers[randomInt(browsers.length)];
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

  function generateIBAN() {
    var countries = [
      { code: 'FR', len: 27 },
      { code: 'DE', len: 22 },
      { code: 'GB', len: 22 },
      { code: 'ES', len: 24 },
      { code: 'IT', len: 27 }
    ];
    var c = countries[randomInt(countries.length)];
    var check = (randomInt(90) + 10).toString();
    var bban = '';
    for (var i = 0; i < c.len - 4; i++) {
      bban += randomInt(10).toString();
    }
    var iban = c.code + check + bban;
    var result = '';
    for (var j = 0; j < iban.length; j += 4) {
      result += (j > 0 ? ' ' : '') + iban.slice(j, j + 4);
    }
    return result;
  }

  function generatePhone() {
    var formats = [
      function () {
        return '+1 (' + (randomInt(800) + 200) + ') ' + (randomInt(900) + 100) + '-' + (randomInt(9000) + 1000);
      },
      function () {
        return '+44 ' + (randomInt(900) + 100) + ' ' + (randomInt(9000) + 1000) + ' ' + (randomInt(9000) + 1000);
      },
      function () {
        return '+33 ' + randomInt(10) + ' ' + (randomInt(90) + 10) + ' ' + (randomInt(90) + 10) + ' ' + (randomInt(90) + 10) + ' ' + (randomInt(90) + 10);
      },
      function () {
        return '+49 ' + (randomInt(900) + 100) + ' ' + (randomInt(90000000) + 10000000);
      }
    ];
    return formats[randomInt(formats.length)]();
  }

  function generateEmail() {
    var names = ['alice', 'bob', 'charlie', 'dave', 'emma', 'frank', 'grace', 'henry', 'iris', 'jack',
      'kate', 'leo', 'mia', 'noah', 'olivia', 'paul', 'quinn', 'ruby', 'sam', 'tara'];
    var domains = ['example.com', 'test.org', 'demo.net', 'sample.io', 'mail.dev', 'acme.co', 'corp.biz'];
    var sep = ['', '.', '_'][randomInt(3)];
    var num = randomInt(2) === 0 ? '' : randomInt(999).toString();
    return names[randomInt(names.length)] + sep + names[randomInt(names.length)] + num + '@' + domains[randomInt(domains.length)];
  }

  function generateAddress() {
    var streets = ['Main', 'Oak', 'Maple', 'Cedar', 'Park', 'High', 'Church', 'Market', 'River', 'Hill',
      'Lake', 'Forest', 'Spring', 'Washington', 'Lincoln', 'Jefferson', 'Rue de la Paix', 'Avenue des Champs'];
    var types = ['St', 'Ave', 'Blvd', 'Rd', 'Dr', 'Ln', 'Way', 'Pl', 'Ct', 'rue', 'avenue', 'boulevard'];
    var cities = ['Paris', 'Lyon', 'Berlin', 'Munich', 'London', 'Manchester', 'Madrid', 'Barcelona', 'New York', 'Los Angeles',
      'Chicago', 'Houston', 'Toronto', 'Montreal', 'Brussels', 'Amsterdam', 'Rome', 'Milan', 'Zurich', 'Vienna'];
    var countries = ['France', 'Germany', 'United Kingdom', 'Spain', 'United States', 'Canada', 'Belgium', 'Netherlands', 'Italy', 'Switzerland', 'Austria'];
    var num = (randomInt(9998) + 1).toString();
    var streetName = streets[randomInt(streets.length)];
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
    var adj = ['swift', 'brave', 'dark', 'wild', 'calm', 'bold', 'keen', 'wise', 'fair', 'warm',
      'cool', 'pure', 'rare', 'vast', 'deep', 'free', 'true', 'rich', 'soft', 'pale'];
    var nouns = ['fox', 'wolf', 'hawk', 'bear', 'lion', 'deer', 'crow', 'sage', 'reed', 'oak',
      'star', 'moon', 'rain', 'wind', 'fire', 'wave', 'stone', 'peak', 'lake', 'dawn'];
    return adj[randomInt(adj.length)] + '_' + nouns[randomInt(nouns.length)] + randomInt(999);
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
    var words = [
      'lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit',
      'sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore', 'et', 'dolore', 'magna',
      'aliqua', 'enim', 'ad', 'minim', 'veniam', 'quis', 'nostrud', 'exercitation', 'ullamco',
      'laboris', 'nisi', 'aliquip', 'ex', 'ea', 'commodo', 'consequat', 'duis', 'aute', 'irure',
      'in', 'reprehenderit', 'voluptate', 'velit', 'esse', 'cillum', 'fugiat', 'nulla', 'pariatur',
      'excepteur', 'sint', 'occaecat', 'cupidatat', 'non', 'proident', 'sunt', 'culpa', 'qui',
      'officia', 'deserunt', 'mollit', 'anim', 'id', 'est', 'laborum'
    ];
    var len = randomInt(12) + 8;
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
    var patterns = [
      '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
      '^\\+?[1-9]\\d{1,14}$',
      '^#?([a-fA-F0-9]{6}|[a-fA-F0-9]{3})$',
      '^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$',
      '^(https?:\\/\\/)?[\\w.-]+\\.[a-z]{2,}(\\/\\S*)?$',
      '^\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$',
      '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
      '^([01]?\\d\\d?|2[0-4]\\d|25[0-5])(\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])){3}$'
    ];
    return patterns[randomInt(patterns.length)];
  }

  function generateHash() {
    return 'sha256:' + bytesToHex(randomBytes(32));
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

  var CARDS = [
    { id: 'password', label: 'Password' },
    { id: 'passphrase', label: 'Passphrase' },
    { id: 'pin', label: 'PIN Code' },
    { id: 'totp', label: 'TOTP Secret' },
    { id: 'uuid', label: 'UUID v4' },
    { id: 'ulid', label: 'ULID' },
    { id: 'nanoid', label: 'NanoID' },
    { id: 'objectid', label: 'MongoDB ObjectId' },
    { id: 'githash', label: 'Git Commit Hash' },
    { id: 'apikey', label: 'API Key' },
    { id: 'jwt', label: 'JWT Token' },
    { id: 'license', label: 'License Key' },
    { id: 'hexcolor', label: 'Hex Color', swatch: true },
    { id: 'rgb', label: 'RGB Color', swatch: true },
    { id: 'hsl', label: 'HSL Color', swatch: true },
    { id: 'mac', label: 'MAC Address' },
    { id: 'ipv4', label: 'IPv4 Address' },
    { id: 'ipv6', label: 'IPv6 Address' },
    { id: 'port', label: 'Port Number' },
    { id: 'cidr', label: 'CIDR Block' },
    { id: 'useragent', label: 'User Agent' },
    { id: 'creditcard', label: 'Credit Card' },
    { id: 'iban', label: 'IBAN' },
    { id: 'phone', label: 'Phone Number' },
    { id: 'email', label: 'Email Address' },
    { id: 'address', label: 'Address' },
    { id: 'username', label: 'Username' },
    { id: 'slug', label: 'URL Slug' },
    { id: 'lorem', label: 'Lorem Ipsum' },
    { id: 'coords', label: 'GPS Coordinates' },
    { id: 'number', label: 'Random Number' },
    { id: 'date', label: 'Random Date' },
    { id: 'timestamp', label: 'Unix Timestamp' },
    { id: 'cron', label: 'CRON Expression' },
    { id: 'regex', label: 'Regex Pattern' },
    { id: 'hash', label: 'SHA-256 Hash' },
    { id: 'flasksecret', label: 'Flask Secret Key' },
    { id: 'djangosecret', label: 'Django Secret Key' },
    { id: 'nonce', label: 'CSP Nonce' },
    { id: 'oauthstate', label: 'OAuth State' },
    { id: 'slugid', label: 'Short Slug ID' },
    { id: 'base64', label: 'Base64 String' },
    { id: 'hex', label: 'Hex String' },
    { id: 'btc', label: 'Bitcoin Address' },
    { id: 'eth', label: 'Ethereum Address' }
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
    var grid = document.getElementById('grid');
    for (var i = 0; i < CARDS.length; i++) {
      var def = CARDS[i];
      var card = document.createElement('div');
      card.className = 'card';
      card.setAttribute('data-generator', def.id);

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

    document.getElementById('grid').addEventListener('click', function (e) {
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

    document.getElementById('regen-all').addEventListener('click', regenerateAll);
  });
})();
