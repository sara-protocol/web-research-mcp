// 检查 ipaddr.js 对 IPv4-mapped IPv6 的处理
// 复制 server.js 中的实际判断逻辑，看是否会被绕过
import ipaddr from 'ipaddr.js';

const DENIED_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
  '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'
].map((cidr) => ipaddr.parseCIDR(cidr));

const DENIED_V6 = [
  '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b:1::/48', '100::/64', '2001::/23',
  '2001:db8::/32', '2002::/16', 'fc00::/7', 'fe80::/10', 'ff00::/8'
].map((cidr) => ipaddr.parseCIDR(cidr));

function isPublicIp(address) {
  try {
    const parsed = ipaddr.process(address);
    if (parsed.range() !== 'unicast') return { ok: false, why: `range=${parsed.range()}` };
    const denylist = parsed.kind() === 'ipv4' ? DENIED_V4 : DENIED_V6;
    const hit = denylist.find((range) => parsed.match(range));
    if (hit) return { ok: false, why: `matched ${hit[1] || hit[0]} (kind=${parsed.kind()})` };
    return { ok: true, kind: parsed.kind(), range: parsed.range() };
  } catch (e) {
    return { ok: false, why: `exception: ${e.message}` };
  }
}

const cases = [
  // 应该被拒（私网）
  ['::ffff:127.0.0.1',       'should REJECT (loopback)'],
  ['::ffff:10.0.0.1',        'should REJECT (private)'],
  ['::ffff:169.254.169.254', 'should REJECT (cloud metadata)'],
  ['::ffff:192.168.1.1',     'should REJECT (private)'],
  ['::ffff:7f00:1',          'should REJECT (loopback hex form)'],
  ['::ffff:c0a8:0101',       'should REJECT (192.168.1.1 hex form)'],
  // 应该允许（公网）
  ['::ffff:8.8.8.8',         'should ACCEPT (public)'],
  ['::ffff:808:808',         'should ACCEPT (public hex form)'],
  ['::ffff:1.1.1.1',         'should ACCEPT (public)'],
  // 纯 IPv6 也应被拒
  ['::1',                    'should REJECT (IPv6 loopback)'],
  ['fe80::1',                'should REJECT (IPv6 link-local)'],
  // 纯 IPv4 也应正常
  ['8.8.8.8',                'should ACCEPT (public IPv4)'],
  ['127.0.0.1',              'should REJECT (IPv4 loopback)'],
];

console.log('='.repeat(80));
console.log('IPv4-mapped IPv6 绕过检查');
console.log('='.repeat(80));
console.log();

let failed = 0;
for (const [addr, expected] of cases) {
  const r = isPublicIp(addr);
  const got = r.ok ? 'ACCEPT' : 'REJECT';
  const should = expected.includes('ACCEPT') ? 'ACCEPT' : 'REJECT';
  const pass = got === should ? '✅' : '❌ MISMATCH';
  if (got !== should) failed++;
  const why = r.ok ? `kind=${r.kind} range=${r.range}` : r.why;
  console.log(`${pass}  ${addr.padEnd(24)} ${got.padEnd(7)} [${expected}]`);
  console.log(`      ${why}`);
}

console.log();
console.log('='.repeat(80));
if (failed === 0) {
  console.log('✅ 全部通过：IPv4-mapped IPv6 未绕过，当前逻辑安全');
} else {
  console.log(`❌ 有 ${failed} 个用例不符合预期 → 存在绕过风险`);
}
console.log('='.repeat(80));