function calculateAssessment(config) {
  let score = 100;
  const findings = [];
  const add = (severity, title, detail, penalty = 0) => { score -= penalty; findings.push({ severity, title, detail }); };

  if (!config.vlans) add("critical", "Réseau non segmenté", "Créez des VLAN distincts pour l’administration, le personnel, les invités et la DMZ. Filtrez les échanges inter-VLAN sur pfSense.", 28);
  else add("good", "Segmentation activée", "Les zones fonctionnelles sont séparées. Appliquez le principe du moindre privilège entre les VLAN.");

  if (config.publicServer && !config.ids) add("high", "Serveur public sans détection", "Activez Suricata ou Snort sur l’interface DMZ et centralisez les alertes afin de détecter les scans et tentatives d’exploitation.", 16);
  if (config.publicServer && !config.vlans) add("critical", "Serveur public dans le réseau interne", "Placez immédiatement le serveur exposé dans une DMZ isolée, sans accès direct vers le LAN.", 20);
  if (config.publicServer && config.vlans) add("good", "Service public isolé", "Le serveur public est placé dans une DMZ dédiée. Limitez les publications NAT aux ports strictement nécessaires.");

  if (config.remoteAccess && !config.mfa) add("high", "Accès distant sans MFA", "Utilisez un VPN IPsec ou OpenVPN et imposez un second facteur. N’exposez jamais RDP ou SSH directement sur Internet.", 17);
  if (config.remoteAccess && config.mfa) add("good", "Accès distant renforcé", "Le MFA réduit le risque lié au vol d’identifiants. Conservez une journalisation des connexions VPN.");

  if (config.guestWifi && !config.vlans) add("critical", "Invités mélangés au réseau interne", "Isolez le Wi-Fi invité dans le VLAN 30 et bloquez tout accès aux réseaux privés RFC1918.", 20);
  if (config.guestWifi && config.vlans) add("medium", "VLAN invités à restreindre", "Autorisez uniquement DNS, DHCP et Internet depuis le VLAN 30. Activez l’isolation des clients sur le point d’accès.", 4);

  if (!config.backups) add("high", "Sauvegardes non garanties", "Appliquez la règle 3-2-1, conservez une copie hors ligne et réalisez un test de restauration documenté.", 16);
  else add("good", "Continuité préparée", "Des sauvegardes testées sont déclarées. Protégez le compte de sauvegarde avec un MFA distinct.");

  if (!config.ids && !config.publicServer) add("medium", "Visibilité limitée", "Ajoutez un IDS/IPS ou, au minimum, une collecte centralisée des journaux pfSense.", 7);
  if (config.ids) add("good", "Surveillance réseau prévue", "Déployez l’IDS d’abord en mode détection, ajustez les règles, puis activez le blocage de manière progressive.");
  if (config.users > 100 && !config.mfa) add("medium", "Parc important sans MFA", "Avec plus de 100 comptes, priorisez le MFA pour les administrateurs, la messagerie et les accès distants.", 8);

  score = Math.max(0, Math.min(100, score));
  const grade = score >= 85 ? "Architecture robuste" : score >= 70 ? "Base maîtrisée" : score >= 50 ? "Renforcement nécessaire" : "Risque important";
  const summary = score >= 85 ? "Les contrôles essentiels sont présents. Maintenez les correctifs et la supervision." : score >= 70 ? "La structure est saine, mais quelques protections doivent être ajoutées." : score >= 50 ? "Plusieurs faiblesses peuvent faciliter une intrusion ou un mouvement latéral." : "Des lacunes majeures exposent les services et les données de l’organisation.";
  const rules = buildFirewallRules(config);
  return { score, grade, summary, findings, rules };
}

function buildFirewallRules(config) {
  const rules = [
    { source: "VLAN 10 Admin", destination: "pfSense", service: "HTTPS, SSH", action: "Autoriser", reason: "Administration depuis une zone dédiée" },
    { source: "VLAN 20 Personnel", destination: "Internet", service: "HTTP(S), DNS, NTP", action: "Autoriser", reason: "Services nécessaires au travail" },
    { source: "Tous VLAN", destination: "VLAN 10 Admin", service: "Tous", action: "Bloquer", reason: "Protection des postes privilégiés" }
  ];
  if (config.guestWifi) {
    rules.push({ source: "VLAN 30 Invités", destination: "Réseaux privés", service: "Tous", action: "Bloquer", reason: "Isolation complète des visiteurs" });
    rules.push({ source: "VLAN 30 Invités", destination: "Internet", service: "HTTP(S), DNS", action: "Autoriser", reason: "Accès Internet uniquement" });
  }
  if (config.publicServer) {
    rules.push({ source: "Internet", destination: "Serveur DMZ", service: "HTTPS 443", action: "Autoriser", reason: "Publication du seul service requis" });
    rules.push({ source: "DMZ 40", destination: "LAN interne", service: "Tous", action: "Bloquer", reason: "Empêcher le mouvement latéral" });
  }
  rules.push({ source: "Tous", destination: "Tous", service: "Tous", action: "Bloquer", reason: "Refus par défaut et journalisation" });
  return rules;
}

function buildLabGuides(config, result) {
  const zones = [
    ["VLAN 10", "Administration", "10.10.10.0/24", "10.10.10.1", "10.10.10.50–10.10.10.99", config.adminDevices],
    ["VLAN 20", "Personnel", "10.10.20.0/24", "10.10.20.1", "10.10.20.50–10.10.20.220", config.staffDevices]
  ];
  if (config.guestWifi) zones.push(["VLAN 30", "Invités", "10.10.30.0/24", "10.10.30.1", "10.10.30.50–10.10.30.240", config.guestDevices]);
  if (config.publicServer) zones.push(["VLAN 40", "DMZ", "10.10.40.0/24", "10.10.40.1", "Statique uniquement", config.serverDevices]);

  const gns3Nodes = zones.map(zone => `   • ${zone[1]} : ${Math.max(1, Math.min(zone[5], 3))} VPCS de démonstration (parmi ${zone[5]} équipements réels)`).join("\n");
  const addressing = zones.map(zone => `   ${zone[0]}  ${zone[1].padEnd(15)} réseau ${zone[2]}  passerelle ${zone[3]}  DHCP ${zone[4]}`).join("\n");
  const ruleLines = result.rules.map((rule, index) => `   ${String(index + 1).padStart(2, "0")}. [${rule.action.toUpperCase()}] ${rule.source} → ${rule.destination} | ${rule.service}\n       ${rule.reason}`).join("\n");
  const total = config.adminDevices + config.staffDevices + (config.guestWifi ? config.guestDevices : 0) + (config.publicServer ? config.serverDevices : 0);

  const gns3 = `NETARCHITECT LAB — PLAN DE MONTAGE GNS3
Organisation : ${config.orgName}
Équipements déclarés : ${total}

1. ÉQUIPEMENTS À AJOUTER
   • 1 nœud NAT GNS3 pour simuler Internet
   • 1 appliance pfSense avec 2 vCPU et 2 Go de RAM
   • 1 Ethernet switch GNS3 configuré en trunk 802.1Q
${gns3Nodes}
${config.guestWifi ? "   • 1 point d’accès générique relié au VLAN 30\n" : ""}${config.publicServer ? "   • 1 serveur léger Ubuntu ou Alpine dans la DMZ\n" : ""}
2. CÂBLAGE
   NAT/Internet → pfSense WAN
   pfSense LAN → Switch port trunk
   Switch → postes et serveurs affectés à leur VLAN

3. PLAN D’ADRESSAGE
${addressing}

4. ORDRE DE DÉMARRAGE
   1) NAT GNS3   2) pfSense   3) Switch   4) Serveurs   5) Postes

5. TESTS DE VALIDATION
   □ Chaque poste reçoit une adresse de son propre VLAN
   □ Les postes atteignent leur passerelle
   □ Le VLAN invités ne peut pas joindre les réseaux privés
   □ La DMZ ne peut pas initier de connexion vers le LAN
   □ Le personnel peut utiliser DNS et HTTPS vers Internet
   □ Les blocages apparaissent dans Status > System Logs > Firewall

Note : dans GNS3, 1 à 3 VPCS par zone suffisent pour représenter un parc plus grand.`;

  const pfsense = `NETARCHITECT LAB — GUIDE DE CONFIGURATION PFSENSE
Organisation : ${config.orgName}
Score initial estimé : ${result.score}/100

1. INTERFACES
   WAN : DHCP depuis le nœud NAT GNS3
   LAN/TRUNK : interface parente reliée au switch

2. CRÉATION DES VLAN
   Menu : Interfaces > Assignments > VLANs
${zones.map(zone => `   • Tag ${zone[0].replace("VLAN ", "")} — ${zone[1]} — interface parente LAN`).join("\n")}

3. AFFECTATION ET ADRESSAGE
   Menu : Interfaces > Assignments
${zones.map(zone => `   • ${zone[1]} : IPv4 statique ${zone[3]}/24`).join("\n")}

4. SERVICES DHCP
   Menu : Services > DHCP Server
${zones.filter(zone => zone[1] !== "DMZ").map(zone => `   • ${zone[1]} : activer la plage ${zone[4]}`).join("\n")}
   • DNS : utiliser pfSense comme résolveur local

5. ALIAS CONSEILLÉS
   PRIVATE_NETS = 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
   ADMIN_NET = 10.10.10.0/24
${config.publicServer ? "   DMZ_SERVERS = adresses statiques des serveurs 10.10.40.x\n" : ""}
6. RÈGLES DE PARE-FEU
${ruleLines}

${config.remoteAccess ? `7. ACCÈS DISTANT
   • Configurer OpenVPN ou IPsec, jamais une redirection directe de RDP/SSH
   • Pool VPN conseillé : 10.10.90.0/24
   • Autoriser uniquement les ressources nécessaires
   • ${config.mfa ? "MFA déclaré : associer un fournisseur TOTP/RADIUS" : "ACTION PRIORITAIRE : activer le MFA pour les utilisateurs VPN"}

` : ""}${config.ids ? `8. IDS/IPS
   • Installer Suricata depuis System > Package Manager
   • Commencer en mode IDS sur WAN et DMZ
   • Observer les faux positifs avant d’activer le blocage
   • Mettre à jour régulièrement les jeux de règles

` : ""}9. SAUVEGARDE ET PREUVE
   • Diagnostics > Backup & Restore : exporter la configuration XML
   • Conserver une capture des règles et des journaux de tests
   • Tester la restauration dans une copie du laboratoire

AVERTISSEMENT
Ce guide est pédagogique. Vérifiez les noms d’interfaces et adaptez toutes les règles avant une utilisation en production.`;

  return { gns3, pfsense };
}

function evaluateTraffic(config, packet) {
  const { source, destination, protocol } = packet;
  const internal = ["admin", "staff", "guest", "dmz"];
  const unavailable = (source === "guest" || destination === "guest") && !config.guestWifi
    || (source === "dmz" || destination === "dmz") && !config.publicServer;
  const middle = source === destination ? "Switch local" : source === "internet" || destination === "internet" || config.vlans ? "pfSense" : "Switch cœur";
  const result = (allowed, reason) => ({ allowed, reason, middle });

  if (unavailable) return result(false, "L’équipement ou la zone sélectionnée n’existe pas dans cette architecture.");
  if (source === destination) return result(true, "Communication locale dans la même zone réseau.");

  if (!config.vlans && internal.includes(source) && internal.includes(destination)) {
    return result(true, "Paquet autorisé par le réseau plat : cette communication illustre un risque de mouvement latéral.");
  }

  if (source === "internet") {
    if (destination === "dmz" && config.publicServer && protocol === "HTTPS") return result(true, "Publication HTTPS autorisée vers le serveur de la DMZ.");
    return result(false, "Le pare-feu bloque les connexions entrantes non publiées depuis Internet.");
  }

  if (destination === "internet") {
    if (["DNS", "HTTP", "HTTPS", "ICMP"].includes(protocol)) return result(true, `${protocol} est autorisé vers Internet avec traduction NAT.`);
    return result(false, `${protocol} n’est pas autorisé vers Internet par la politique proposée.`);
  }

  if (source === "guest") return result(false, "Le VLAN 30 Invités est isolé de tous les réseaux privés.");
  if (source === "dmz" && ["admin", "staff", "guest"].includes(destination)) return result(false, "La DMZ ne peut pas initier de connexion vers le réseau interne.");
  if (destination === "admin" && source !== "admin") return result(false, "Le VLAN Administration accepte uniquement les flux explicitement autorisés depuis sa propre zone.");
  if (source === "admin") return result(true, "Le poste d’administration est autorisé pour cette opération de gestion.");
  if (source === "staff" && destination === "dmz" && ["HTTP", "HTTPS"].includes(protocol)) return result(true, "Le personnel peut consulter le service web hébergé dans la DMZ.");
  if (source === "staff" && destination === "guest") return result(false, "Les réseaux Personnel et Invités sont isolés.");
  return result(false, "Le refus par défaut de pfSense bloque ce flux non déclaré.");
}

const deviceCounts = { adminDevices: 4, staffDevices: 35, guestDevices: 20, serverDevices: 2 };

function readConfig() {
  return {
    orgName: document.querySelector("#org-name").value.trim(),
    users: Number(document.querySelector("#users").value),
    guestWifi: document.querySelector("#guest-wifi").checked,
    publicServer: document.querySelector("#public-server").checked,
    remoteAccess: document.querySelector("#remote-access").checked,
    vlans: document.querySelector("#vlans").checked,
    ids: document.querySelector("#ids").checked,
    mfa: document.querySelector("#mfa").checked,
    backups: document.querySelector("#backups").checked,
    ...deviceCounts
  };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
}

function normalizeExerciseText(value) {
  return String(value || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
}

function parseNetworkExercise(text) {
  const source = String(text || "").trim();
  const normalized = normalizeExerciseText(source);
  const numberWords = { un: 1, une: 1, deux: 2, trois: 3, quatre: 4, cinq: 5, six: 6, sept: 7, huit: 8, neuf: 9, dix: 10 };
  const readCount = labels => {
    const labelPattern = labels.join("|");
    const digit = normalized.match(new RegExp(`(\\d+)\\s*(?:${labelPattern})\\b`));
    if (digit) return Number(digit[1]);
    const word = normalized.match(new RegExp(`\\b(${Object.keys(numberWords).join("|")})\\s+(?:${labelPattern})\\b`));
    return word ? numberWords[word[1]] : 0;
  };
  const has = pattern => pattern.test(normalized);
  const users = readCount(["utilisateurs?", "employes?", "personnes?"]);
  const pcs = readCount(["postes?", "ordinateurs?", "pcs?", "machines?"]) || users;
  const servers = readCount(["serveurs?"]) || (has(/serveur|dmz/) ? 1 : 0);
  const switches = readCount(["switchs?", "commutateurs?"]) || (has(/switch|commutateur|vlan|reseau/) ? 1 : 0);
  const routers = readCount(["routeurs?"]) || (has(/routeur/) ? 1 : 0);
  const accessPoints = readCount(["points? d[' ]?acces", "bornes? (?:wi-?fi|wifi)"]) || (has(/wi-?fi|wifi|point d[' ]?acces/) ? 1 : 0);
  const internet = has(/internet|\bwan\b|\bfai\b|connexion externe/) || source.length > 0;
  const firewall = has(/pfsense|pare[- ]?feu|firewall/) || internet;
  const dmz = has(/\bdmz\b|serveur (?:web|public|expose)/);
  const wifi = accessPoints > 0 || has(/invite|visiteur/);

  const zoneCatalog = [
    { test: /administration|administratif|direction/, id: 10, name: "Administration" },
    { test: /personnel|employe|utilisateur|bureau/, id: 20, name: "Personnel" },
    { test: /invite|visiteur|guest/, id: 30, name: "Invités" },
    { test: /\bdmz\b|serveur/, id: 40, name: "DMZ / Serveurs" }
  ];
  const explicitIds = [...normalized.matchAll(/vlan\s*(?:n[o°]?\s*)?(\d{1,4})/g)].map(match => Number(match[1]));
  const vlans = [];
  zoneCatalog.forEach(zone => {
    if (zone.test.test(normalized)) vlans.push({ id: zone.id, name: zone.name, subnet: `10.10.${zone.id}.0/24` });
  });
  explicitIds.forEach((id, index) => {
    if (!vlans.some(vlan => vlan.id === id)) vlans.push({ id, name: `Réseau ${index + 1}`, subnet: `10.10.${id}.0/24` });
  });
  if (has(/vlan|segment|separer|isoler/) && !vlans.length) {
    vlans.push(
      { id: 10, name: "Administration", subnet: "10.10.10.0/24" },
      { id: 20, name: "Personnel", subnet: "10.10.20.0/24" }
    );
  }
  if (!vlans.length && source) vlans.push({ id: 20, name: "Réseau local", subnet: "10.10.20.0/24" });

  const warnings = [];
  if (source.length < 25) warnings.push("Énoncé très court : ajoutez les équipements et les zones pour un schéma plus précis.");
  if (!pcs && !users) warnings.push("Aucun nombre de postes ou d’utilisateurs détecté.");
  if (!has(/switch|commutateur/) && switches) warnings.push("Un switch a été ajouté pour relier les équipements détectés.");
  if (!has(/pfsense|pare[- ]?feu|firewall/) && firewall) warnings.push("Un pare-feu a été ajouté entre Internet et le réseau interne.");

  return {
    source, users: users || pcs || 1, pcs: pcs || users || 1, servers, switches, routers,
    accessPoints, internet, firewall, dmz, wifi, vlans, warnings
  };
}

function buildNetworkSvg(network) {
  const width = 1000;
  const height = 570;
  const core = [];
  if (network.internet) core.push({ label: "INTERNET", detail: "WAN / FAI", kind: "internet" });
  if (network.routers) core.push({ label: "ROUTEUR", detail: `${network.routers} équipement${network.routers > 1 ? "s" : ""}`, kind: "router" });
  if (network.firewall) core.push({ label: "PARE-FEU", detail: "pfSense / filtrage", kind: "firewall" });
  if (network.switches) core.push({ label: "SWITCH CŒUR", detail: `${network.switches} commutateur${network.switches > 1 ? "s" : ""}`, kind: "switch" });
  if (!core.length) core.push({ label: "RÉSEAU", detail: "Topologie proposée", kind: "switch" });

  const branches = network.vlans.slice(0, 5).map(vlan => ({
    label: `VLAN ${vlan.id} — ${vlan.name}`,
    detail: vlan.name.includes("Serveur") || vlan.name.includes("DMZ") ? `${network.servers || 1} serveur(s)` : vlan.name === "Invités" ? `${network.accessPoints || 1} point(s) Wi-Fi` : `${network.pcs || network.users} poste(s)`,
    subnet: vlan.subnet
  }));
  if (network.wifi && !branches.some(branch => /Invite|Wi-Fi/.test(branch.label))) branches.push({ label: "WI-FI", detail: `${network.accessPoints || 1} point(s) d’accès`, subnet: "Réseau sans fil" });
  if (network.dmz && !branches.some(branch => /DMZ|Serveur/.test(branch.label))) branches.push({ label: "DMZ", detail: `${network.servers || 1} serveur(s)`, subnet: "Zone isolée" });
  const visibleBranches = branches.slice(0, 5);
  const coreGap = core.length > 1 ? 235 / (core.length - 1) : 0;
  const coreNodes = core.map((node, index) => ({ ...node, x: 500, y: 55 + index * coreGap }));
  const lastCore = coreNodes[coreNodes.length - 1];
  const branchY = 430;
  const branchGap = width / (visibleBranches.length + 1);
  const branchNodes = visibleBranches.map((node, index) => ({ ...node, x: branchGap * (index + 1), y: branchY }));
  const lines = [];
  for (let index = 1; index < coreNodes.length; index += 1) lines.push(`<line x1="500" y1="${coreNodes[index - 1].y + 38}" x2="500" y2="${coreNodes[index].y - 38}" />`);
  branchNodes.forEach(node => lines.push(`<path d="M ${lastCore.x} ${lastCore.y + 38} V 380 H ${node.x} V ${node.y - 45}" />`));
  const coreMarkup = coreNodes.map(node => `<g class="schema-node ${node.kind}" transform="translate(${node.x - 105} ${node.y - 38})"><rect width="210" height="76" rx="14"/><circle cx="28" cy="25" r="8"/><text class="node-title" x="48" y="29">${escapeHtml(node.label)}</text><text class="node-detail" x="20" y="56">${escapeHtml(node.detail)}</text></g>`).join("");
  const branchMarkup = branchNodes.map(node => `<g class="schema-node branch" transform="translate(${node.x - 86} ${node.y - 45})"><rect width="172" height="90" rx="13"/><text class="node-title centered-title" x="86" y="28">${escapeHtml(node.label)}</text><text class="node-detail centered-title" x="86" y="51">${escapeHtml(node.detail)}</text><text class="node-subnet centered-title" x="86" y="72">${escapeHtml(node.subnet)}</text></g>`).join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="schema-title schema-desc"><title id="schema-title">Schéma réseau généré depuis l’exercice</title><desc id="schema-desc">Topologie reliant Internet, les équipements réseau et les zones VLAN détectées.</desc><style>.bg{fill:#06110f}.grid{stroke:#14332c;stroke-width:1;opacity:.35}.links line,.links path{fill:none;stroke:#38dba0;stroke-width:3;stroke-linecap:round;stroke-linejoin:round}.schema-node rect{fill:#0d211d;stroke:#2b6655;stroke-width:2}.schema-node circle{fill:#3af2ad}.schema-node.firewall rect{stroke:#3af2ad;stroke-width:3}.schema-node.internet rect{stroke:#4cb6ff}.schema-node.branch rect{fill:#0a1a17}.node-title{fill:#eafff7;font:700 15px Arial,sans-serif}.node-detail{fill:#91afa5;font:12px Arial,sans-serif}.node-subnet{fill:#3af2ad;font:11px monospace}.centered-title{text-anchor:middle}.caption{fill:#66877c;font:12px Arial,sans-serif;letter-spacing:2px}</style><rect class="bg" width="1000" height="570" rx="18"/><defs><pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path class="grid" d="M32 0H0V32" fill="none"/></pattern></defs><rect width="1000" height="570" fill="url(#grid)"/><text class="caption" x="28" y="35">NETARCHITECT LAB — TOPOLOGIE GÉNÉRÉE</text><g class="links">${lines.join("")}</g>${coreMarkup}${branchMarkup}</svg>`;
}

function render(config, result) {
  document.querySelector("#score").textContent = result.score;
  document.querySelector("#hero-score").textContent = `${result.score}/100`;
  document.querySelector("#grade").textContent = result.grade;
  document.querySelector("#score-summary").textContent = result.summary;
  document.querySelector("#score-ring").style.setProperty("--score-angle", `${result.score * 3.6}deg`);
  document.querySelector("#critical-count").textContent = result.findings.filter(f => f.severity === "critical").length;
  document.querySelector("#high-count").textContent = result.findings.filter(f => f.severity === "high").length;
  document.querySelector("#action-count").textContent = result.findings.filter(f => f.severity !== "good").length;
  document.querySelector("#guest-node").classList.toggle("hidden", !config.guestWifi);
  document.querySelector("#dmz-node").classList.toggle("hidden", !config.publicServer);

  const labels = { critical: "Critique", high: "Élevé", medium: "Conseil", good: "Conforme" };
  const icons = { critical: "!", high: "△", medium: "i", good: "✓" };
  document.querySelector("#findings").className = "findings-list";
  document.querySelector("#findings").innerHTML = result.findings.map(f => `
    <article class="finding ${f.severity}"><span class="finding-icon">${icons[f.severity]}</span><div><h3>${escapeHtml(f.title)}</h3><p>${escapeHtml(f.detail)}</p></div><span class="severity">${labels[f.severity]}</span></article>
  `).join("");

  document.querySelector("#rules-body").innerHTML = result.rules.map(rule => `
    <tr><td>${escapeHtml(rule.source)}</td><td>${escapeHtml(rule.destination)}</td><td>${escapeHtml(rule.service)}</td><td class="${rule.action === "Autoriser" ? "allow" : "block"}">${rule.action}</td><td>${escapeHtml(rule.reason)}</td></tr>
  `).join("");
  document.querySelector("#download-btn").disabled = false;
  window.netarchitectGuides = buildLabGuides(config, result);
  window.activeGuide = "gns3";
  document.querySelector("#guide-output").textContent = window.netarchitectGuides.gns3;
  document.querySelectorAll(".guide-tab").forEach(tab => {
    const active = tab.dataset.guide === "gns3";
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  document.querySelector("#copy-guide-btn").disabled = false;
  document.querySelector("#download-lab-btn").disabled = false;
  localStorage.setItem("netarchitect-last-config", JSON.stringify(config));
  window.netarchitectReport = { config, result };
}

function reportHtml({ config, result }) {
  const date = new Intl.DateTimeFormat("fr-FR", { dateStyle: "long" }).format(new Date());
  return `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Rapport NetArchitect Lab — ${escapeHtml(config.orgName)}</title><style>body{font:14px Arial;color:#13201c;max-width:900px;margin:40px auto;padding:0 24px}h1{color:#087b55}h2{margin-top:32px;border-bottom:2px solid #1ab47d;padding-bottom:8px}table{width:100%;border-collapse:collapse}th,td{padding:9px;border:1px solid #ccd8d3;text-align:left}th{background:#edf8f3}.score{font-size:38px;font-weight:bold;color:#087b55}.note{background:#fff6df;padding:12px;border-left:4px solid #e7a929}.critical{color:#bd233c}.high{color:#a26400}.good{color:#087b55}@media print{button{display:none}}</style><body><h1>Rapport d’analyse réseau</h1><p><b>Organisation :</b> ${escapeHtml(config.orgName)}<br><b>Utilisateurs :</b> ${config.users}<br><b>Date :</b> ${date}</p><p class="score">${result.score}/100 — ${result.grade}</p><p>${result.summary}</p><p class="note">Rapport pédagogique : toute règle doit être adaptée et validée avant une mise en production.</p><h2>Constats</h2>${result.findings.map(f => `<h3 class="${f.severity}">${escapeHtml(f.title)}</h3><p>${escapeHtml(f.detail)}</p>`).join("")}<h2>Règles pfSense proposées</h2><table><tr><th>Source</th><th>Destination</th><th>Service</th><th>Action</th><th>Justification</th></tr>${result.rules.map(r => `<tr><td>${escapeHtml(r.source)}</td><td>${escapeHtml(r.destination)}</td><td>${escapeHtml(r.service)}</td><td>${r.action}</td><td>${escapeHtml(r.reason)}</td></tr>`).join("")}</table><h2>Topologie d’adressage</h2><ul><li>VLAN 10 — Administration — 10.10.10.0/24</li><li>VLAN 20 — Personnel — 10.10.20.0/24</li>${config.guestWifi ? "<li>VLAN 30 — Invités — 10.10.30.0/24</li>" : ""}${config.publicServer ? "<li>DMZ 40 — Serveurs publics — 10.10.40.0/24</li>" : ""}</ul><button onclick="print()">Imprimer / Enregistrer en PDF</button></body></html>`;
}

if (typeof document !== "undefined") {
  const equipmentLabels = { admin: "PC Administration", staff: "PC Personnel", guest: "Appareil invité", dmz: "Serveur DMZ", internet: "Machine Internet" };
  let simulationHistory = [];

  const updateEquipmentRack = () => {
    document.querySelector("#rack-ap").classList.toggle("offline", !document.querySelector("#guest-wifi").checked);
    document.querySelector("#rack-server").classList.toggle("offline", !document.querySelector("#public-server").checked);
  };
  document.querySelectorAll("#guest-wifi, #public-server").forEach(input => input.addEventListener("change", updateEquipmentRack));
  updateEquipmentRack();

  const renderExerciseSchema = () => {
    const exercise = document.querySelector("#exercise-text").value;
    if (!exercise.trim()) {
      document.querySelector("#generated-schema").className = "generated-schema empty-schema";
      document.querySelector("#generated-schema").innerHTML = "<div><b>Ajoutez d’abord un exercice</b><span>Décrivez le réseau demandé par le professeur.</span></div>";
      return;
    }
    const parsed = parseNetworkExercise(exercise);
    const svg = buildNetworkSvg(parsed);
    window.generatedNetworkSvg = svg;
    document.querySelector("#generated-schema").className = "generated-schema";
    document.querySelector("#generated-schema").innerHTML = svg;
    const detected = [
      `${parsed.users} utilisateur(s)`, `${parsed.switches} switch(s)`,
      parsed.firewall ? "Pare-feu" : null, parsed.routers ? `${parsed.routers} routeur(s)` : null,
      parsed.wifi ? "Wi-Fi" : null, parsed.dmz ? "DMZ" : null,
      `${parsed.vlans.length} zone(s) réseau`
    ].filter(Boolean);
    document.querySelector("#detected-items").innerHTML = detected.map(item => `<span class="detected-chip">✓ ${escapeHtml(item)}</span>`).join("") + parsed.warnings.map(item => `<span class="detected-warning">△ ${escapeHtml(item)}</span>`).join("");
    document.querySelector("#download-schema-btn").disabled = false;

    document.querySelector("#users").value = parsed.users;
    document.querySelector("#guest-wifi").checked = parsed.wifi;
    document.querySelector("#public-server").checked = parsed.dmz || parsed.servers > 0;
    document.querySelector("#vlans").checked = parsed.vlans.length > 1;
    deviceCounts.adminDevices = Math.max(1, Math.round(parsed.users * .1));
    deviceCounts.staffDevices = Math.max(1, parsed.users - deviceCounts.adminDevices);
    deviceCounts.guestDevices = parsed.wifi ? Math.max(1, Math.round(parsed.users * .25)) : 1;
    deviceCounts.serverDevices = Math.max(1, parsed.servers);
    document.querySelectorAll(".node-counter").forEach(counter => { counter.querySelector("strong").textContent = deviceCounts[counter.dataset.counter]; });
    updateEquipmentRack();
    const config = readConfig();
    render(config, calculateAssessment(config));
  };

  document.querySelector("#exercise-example-btn").addEventListener("click", () => {
    document.querySelector("#exercise-text").value = "Une entreprise de 45 utilisateurs possède un accès Internet, un pare-feu pfSense et un switch. Séparer l’administration, le personnel et les invités avec les VLAN 10, 20 et 30. Installer un point d’accès Wi-Fi pour les invités et placer un serveur web public dans une DMZ VLAN 40.";
    renderExerciseSchema();
  });
  document.querySelector("#generate-schema-btn").addEventListener("click", renderExerciseSchema);
  document.querySelector("#download-schema-btn").addEventListener("click", () => {
    if (!window.generatedNetworkSvg) return;
    const blob = new Blob([window.generatedNetworkSvg], { type: "image/svg+xml;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "schema-reseau-netarchitect.svg";
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  });

  const renderSimulationLog = () => {
    const body = document.querySelector("#simulation-log-body");
    if (!simulationHistory.length) {
      body.innerHTML = '<tr><td colspan="6" class="table-empty">Aucun paquet simulé.</td></tr>';
      return;
    }
    body.innerHTML = simulationHistory.map(item => `<tr><td>${item.time}</td><td>${escapeHtml(equipmentLabels[item.source])}</td><td>${escapeHtml(equipmentLabels[item.destination])}</td><td>${escapeHtml(item.protocol)}</td><td class="${item.allowed ? "decision-allow" : "decision-block"}">${item.allowed ? "AUTORISÉ" : "BLOQUÉ"}</td><td>${escapeHtml(item.reason)}</td></tr>`).join("");
  };

  document.querySelectorAll(".node-counter").forEach(counter => {
    const key = counter.dataset.counter;
    const output = counter.querySelector("strong");
    const buttons = counter.querySelectorAll("button");
    const limits = key === "serverDevices" ? [1, 20] : [1, 500];
    buttons[0].addEventListener("click", () => {
      deviceCounts[key] = Math.max(limits[0], deviceCounts[key] - 1);
      output.textContent = deviceCounts[key];
    });
    buttons[1].addEventListener("click", () => {
      deviceCounts[key] = Math.min(limits[1], deviceCounts[key] + 1);
      output.textContent = deviceCounts[key];
    });
  });
  document.querySelector("#config-form").addEventListener("submit", event => {
    event.preventDefault();
    const config = readConfig();
    render(config, calculateAssessment(config));
    document.querySelector("#results").scrollIntoView({ behavior: "smooth", block: "center" });
  });
  document.querySelector("#packet-form").addEventListener("submit", event => {
    event.preventDefault();
    const config = readConfig();
    const packet = {
      source: document.querySelector("#packet-source").value,
      destination: document.querySelector("#packet-destination").value,
      protocol: document.querySelector("#packet-protocol").value
    };
    const verdict = evaluateTraffic(config, packet);
    document.querySelector("#route-source").textContent = equipmentLabels[packet.source];
    document.querySelector("#route-middle").textContent = verdict.middle;
    document.querySelector("#route-destination").textContent = equipmentLabels[packet.destination];
    const dots = document.querySelectorAll(".route-wire i");
    dots.forEach(dot => { dot.className = ""; void dot.offsetWidth; });
    dots[0].className = `moving ${verdict.allowed ? "" : "blocked"}`;
    setTimeout(() => { dots[1].className = `moving ${verdict.allowed ? "" : "blocked"}`; }, 620);
    const resultBox = document.querySelector("#packet-result");
    resultBox.className = `packet-result ${verdict.allowed ? "allowed" : "blocked"}`;
    resultBox.innerHTML = `<b>${verdict.allowed ? "✓ Paquet autorisé" : "✕ Paquet bloqué"}</b><span>${escapeHtml(verdict.reason)}</span>`;
    simulationHistory.unshift({ ...packet, ...verdict, time: new Date().toLocaleTimeString("fr-FR") });
    simulationHistory = simulationHistory.slice(0, 12);
    renderSimulationLog();
  });
  document.querySelector("#clear-log").addEventListener("click", () => {
    simulationHistory = [];
    renderSimulationLog();
    const resultBox = document.querySelector("#packet-result");
    resultBox.className = "packet-result idle";
    resultBox.innerHTML = "<b>Prêt pour la simulation</b><span>Choisissez un flux puis envoyez le paquet.</span>";
  });
  document.querySelector("#demo-btn").addEventListener("click", () => {
    document.querySelector("#org-name").value = "Clinique Horizon";
    document.querySelector("#users").value = 120;
    document.querySelector("#guest-wifi").checked = true;
    document.querySelector("#public-server").checked = true;
    document.querySelector("#remote-access").checked = true;
    document.querySelector("#vlans").checked = true;
    document.querySelector("#ids").checked = true;
    document.querySelector("#mfa").checked = true;
    document.querySelector("#backups").checked = true;
    updateEquipmentRack();
  });
  document.querySelector("#download-btn").addEventListener("click", () => {
    const html = reportHtml(window.netarchitectReport);
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `rapport-netarchitect-${window.netarchitectReport.config.orgName.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.html`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  });
  document.querySelectorAll(".guide-tab").forEach(tab => tab.addEventListener("click", () => {
    if (!window.netarchitectGuides) return;
    window.activeGuide = tab.dataset.guide;
    document.querySelectorAll(".guide-tab").forEach(item => {
      const active = item === tab;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
    });
    document.querySelector("#guide-output").textContent = window.netarchitectGuides[window.activeGuide];
  }));
  document.querySelector("#copy-guide-btn").addEventListener("click", async event => {
    const text = window.netarchitectGuides?.[window.activeGuide];
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = document.createElement("textarea");
      area.value = text;
      document.body.append(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    event.currentTarget.textContent = "Copié ✓";
    setTimeout(() => { event.currentTarget.textContent = "Copier"; }, 1400);
  });
  document.querySelector("#download-lab-btn").addEventListener("click", () => {
    if (!window.netarchitectGuides) return;
    const content = `${window.netarchitectGuides.gns3}\n\n${"=".repeat(72)}\n\n${window.netarchitectGuides.pfsense}`;
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "netarchitect-guides-gns3-pfsense.txt";
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { calculateAssessment, buildFirewallRules, buildLabGuides, evaluateTraffic, parseNetworkExercise, buildNetworkSvg };
}
