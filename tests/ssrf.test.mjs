// tests/ssrf.test.mjs
// SSRF 回归测试 —— 47 个用例,离线运行(node --test)。

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

// server.js performs a startup check on MCP_BEARER_TOKEN at module load time
// and calls process.exit(1) if it is missing. In CI there is no .env file,
// so we set a dummy value BEFORE importing the module.
// This only affects the module's startup check; the actual tests never send
// authenticated requests.
process.env.MCP_BEARER_TOKEN = process.env.MCP_BEARER_TOKEN || 'a'.repeat(64);
process.env.BRAVE_SEARCH_API_KEY = process.env.BRAVE_SEARCH_API_KEY || 'dummy';


const { isPublicIp, validateAndResolvePublicUrl } = await import('../src/server.js');

describe('isPublicIp — IPv4', () => {
  const publicOnes = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '100.63.255.255', '198.20.0.1'];
  const privateOnes = [
    '0.0.0.0', '0.1.2.3', '10.0.0.1', '10.255.255.255', '100.64.0.1', '100.127.255.255',
    '127.0.0.1', '127.255.255.254', '169.254.169.254', '172.16.0.1', '172.31.255.255',
    '192.0.0.1', '192.168.1.1', '198.18.0.1', '198.19.255.255', '224.0.0.1', '240.0.0.1',
    '255.255.255.255'
  ];
  for (const ip of publicOnes) test('public: ' + ip, () => assert.equal(isPublicIp(ip), true));
  for (const ip of privateOnes) test('non-public: ' + ip, () => assert.equal(isPublicIp(ip), false));
  test('malformed input → false', () => {
    for (const bad of ['', '1.2.3.4.5', '256.1.1.1', 'a.b.c.d', 'not-an-ip', null, undefined]) {
      assert.equal(isPublicIp(bad), false, 'input: ' + String(bad));
    }
  });
});

describe('isPublicIp — IPv6', () => {
  const publicOnes = ['2606:4700:4700::1111', '2001:4860:4860::8888'];
  const privateOnes = [
    '::', '::1',
    '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:169.254.169.254',
    '2001:db8::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1'
  ];
  for (const ip of publicOnes) test('public: ' + ip, () => assert.equal(isPublicIp(ip), true));
  for (const ip of privateOnes) test('non-public: ' + ip, () => assert.equal(isPublicIp(ip), false));
  test('IPv4-mapped public address → true', () => {
    assert.equal(isPublicIp('::ffff:8.8.8.8'), true);
    assert.equal(isPublicIp('::ffff:1.1.1.1'), true);
  });
  test('IPv4-mapped private address → false', () => {
    assert.equal(isPublicIp('::ffff:7f00:1'), false);
    assert.equal(isPublicIp('::ffff:c0a8:0101'), false);
  });
});

describe('validateAndResolvePublicUrl — rejected', () => {
  const cases = [
    ['ftp://example.com/',                   /Only http and https/],
    ['file:///etc/passwd',                   /Only http and https/],
    ['gopher://example.com/',                /Only http and https/],
    ['javascript:alert(1)',                  /Invalid URL|Only http and https/],
    ['https://user:pass@example.com/',       /credentials/],
    ['https://user@example.com/',            /credentials/],
    ['http://example.com:8080/',             /Non-standard ports/],
    ['https://example.com:80/',              /Non-standard ports/],
    ['http://example.com:443/',              /Non-standard ports/],
    ['http://localhost/',                    /Local, internal/],
    ['http://localhost./',                   /Local, internal/],
    ['http://LOCALHOST/',                    /Local, internal/],
    ['http://foo.localhost/',                /Local, internal/],
    ['http://printer.local/',                /Local, internal/],
    ['http://db.internal/',                  /Local, internal/],
    ['http://127.0.0.1/',                    /Non-public/],
    ['http://127.1/',                        /Non-public/],
    ['http://2130706433/',                   /Non-public/],
    ['http://0x7f000001/',                   /Non-public/],
    ['http://0177.0.0.1/',                   /Non-public/],
    ['http://[::1]/',                        /Non-public/],
    ['http://[::ffff:127.0.0.1]/',           /Non-public/],
    ['http://[fe80::1]/',                    /Non-public/],
    ['http://169.254.169.254/latest/meta-data/', /Non-public/],
    ['http://10.0.0.5/',                     /Non-public/],
    ['http://192.168.0.1/',                  /Non-public/],
    ['http://[fd00::1]/',                    /Non-public/],
    ['not a url',                            /Invalid URL/],
    ['',                                     /Invalid URL/]
  ];
  for (const [input, pattern] of cases) {
    test('reject ' + (input || '(empty)'), async () => {
      await assert.rejects(
        () => validateAndResolvePublicUrl(input),
        (e) => pattern.test(e.message),
        'expected ' + JSON.stringify(input) + ' to reject with ' + pattern
      );
    });
  }
  test('@ trick: host after @ counts', async () => {
    await assert.rejects(
      () => validateAndResolvePublicUrl('http://example.com@127.0.0.1/'),
      /credentials|Non-public/
    );
  });
});

describe('validateAndResolvePublicUrl — accepted (public IP literals)', () => {
  test('https://8.8.8.8/', async () => {
    const r = await validateAndResolvePublicUrl('https://8.8.8.8/');
    assert.equal(r.hostname, '8.8.8.8');
  });
  test('http://93.184.216.34/', async () => {
    const r = await validateAndResolvePublicUrl('http://93.184.216.34/');
    assert.equal(r.hostname, '93.184.216.34');
  });
  test('https://[2606:4700:4700::1111]/', async () => {
    const r = await validateAndResolvePublicUrl('https://[2606:4700:4700::1111]/');
    assert.match(r.hostname, /2606:4700:4700::1111/);
  });
});

describe('regression: v4/v6 rules do not interfere', () => {
  test('public IPv4 still public after IPv6 checks', () => {
    assert.equal(isPublicIp('2001:db8::1'), false);
    assert.equal(isPublicIp('8.8.8.8'), true);
    assert.equal(isPublicIp('::1'), false);
    assert.equal(isPublicIp('93.184.216.34'), true);
  });
});
