const test = require("node:test");
const assert = require("node:assert/strict");
const { calculateAssessment, buildFirewallRules, buildLabGuides, evaluateTraffic, parseNetworkExercise, buildNetworkSvg } = require("../app.js");

const secure = { orgName: "Test", users: 50, guestWifi: true, publicServer: true, remoteAccess: true, vlans: true, ids: true, mfa: true, backups: true, adminDevices: 4, staffDevices: 35, guestDevices: 20, serverDevices: 2 };

test("une architecture complète obtient un score élevé", () => {
  const result = calculateAssessment(secure);
  assert.ok(result.score >= 85);
  assert.equal(result.findings.some(f => f.severity === "critical"), false);
});

test("un réseau plat exposé produit des constats critiques", () => {
  const result = calculateAssessment({ ...secure, vlans: false, ids: false, mfa: false, backups: false });
  assert.ok(result.score < 50);
  assert.ok(result.findings.filter(f => f.severity === "critical").length >= 2);
});

test("les règles incluent l’isolation des invités et de la DMZ", () => {
  const rules = buildFirewallRules(secure);
  assert.ok(rules.some(r => r.source.includes("Invités") && r.action === "Bloquer"));
  assert.ok(rules.some(r => r.source.includes("DMZ") && r.destination.includes("LAN")));
});

test("le score reste borné entre 0 et 100", () => {
  const weak = calculateAssessment({ users: 500, guestWifi: true, publicServer: true, remoteAccess: true, vlans: false, ids: false, mfa: false, backups: false });
  assert.ok(weak.score >= 0 && weak.score <= 100);
});

test("les guides GNS3 et pfSense reflètent l’architecture", () => {
  const assessment = calculateAssessment(secure);
  const guides = buildLabGuides(secure, assessment);
  assert.match(guides.gns3, /NAT GNS3/);
  assert.match(guides.gns3, /VLAN invités ne peut pas joindre/);
  assert.match(guides.pfsense, /Tag 40 — DMZ/);
  assert.match(guides.pfsense, /OpenVPN ou IPsec/);
});

test("le simulateur autorise HTTPS du personnel vers Internet", () => {
  const verdict = evaluateTraffic(secure, { source: "staff", destination: "internet", protocol: "HTTPS" });
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.middle, "pfSense");
});

test("le simulateur bloque les invités vers l’administration", () => {
  const verdict = evaluateTraffic(secure, { source: "guest", destination: "admin", protocol: "ICMP" });
  assert.equal(verdict.allowed, false);
  assert.match(verdict.reason, /isolé/);
});

test("un réseau plat illustre le mouvement latéral", () => {
  const verdict = evaluateTraffic({ ...secure, vlans: false }, { source: "staff", destination: "admin", protocol: "RDP" });
  assert.equal(verdict.allowed, true);
  assert.match(verdict.reason, /mouvement latéral/);
});

test("un énoncé du professeur est transformé en équipements et VLAN", () => {
  const parsed = parseNetworkExercise("Une école de 80 utilisateurs possède Internet, un routeur, un pare-feu pfSense et deux switchs. Séparer l'administration et les invités avec les VLAN 10 et 30. Ajouter un serveur web dans une DMZ VLAN 40 et un point d'accès Wi-Fi.");
  assert.equal(parsed.users, 80);
  assert.equal(parsed.routers, 1);
  assert.equal(parsed.switches, 2);
  assert.equal(parsed.wifi, true);
  assert.equal(parsed.dmz, true);
  assert.ok(parsed.vlans.some(vlan => vlan.id === 40));
});

test("le générateur produit un SVG autonome avec les équipements détectés", () => {
  const parsed = parseNetworkExercise("Un réseau de 20 postes avec Internet, pfSense, un switch et un serveur web en DMZ.");
  const svg = buildNetworkSvg(parsed);
  assert.match(svg, /^<svg/);
  assert.match(svg, /PARE-FEU/);
  assert.match(svg, /SWITCH CŒUR/);
  assert.match(svg, /DMZ/);
  assert.match(svg, /<\/svg>$/);
});
