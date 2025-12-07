require("dotenv").config();
const {
  Client,
  GatewayIntentBits,
  Partials,
  AuditLogEvent,
  EmbedBuilder
} = require("discord.js");
const fs = require("fs");
const path = require("path");

const config = require("./config.json");

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel]
});

// --- Simple local logging (prototype) ---
const LOG_FILE = path.join(__dirname, "validify-log.json");

function logEvent(event) {
  try {
    const existing = fs.existsSync(LOG_FILE)
      ? JSON.parse(fs.readFileSync(LOG_FILE, "utf8"))
      : [];
    existing.push({ ...event, ts: new Date().toISOString() });
    fs.writeFileSync(LOG_FILE, JSON.stringify(existing, null, 2));
  } catch (e) {
    console.error("Log write error:", e);
  }
}

function getAlertChannel(guild) {
  return guild.channels.cache.get(config.ALERT_CHANNEL_ID) || null;
}

function buildEmbed(title, description, color = 0x00ff88) {
  return new EmbedBuilder()
    .setTitle(title)
    .setDescription(description)
    .setColor(color)
    .setTimestamp(new Date());
}

// --- Link analysis (very basic, safe prototype) ---
function extractUrls(text) {
  const urlRegex = /(https?:\/\/[^\s]+)/gi;
  return text.match(urlRegex) || [];
}

function getDomain(url) {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isAllowlisted(domain) {
  return config.ALLOWLIST_DOMAINS.some(d => domain.endsWith(d));
}

function isSuspiciousDomain(domain) {
  return config.SUSPICIOUS_DOMAINS.some(d => domain.includes(d));
}

function containsSuspiciousKeyword(text) {
  const lower = text.toLowerCase();
  return config.SUSPICIOUS_KEYWORDS.some(k => lower.includes(k));
}

// --- Ready ---
client.once("ready", () => {
  console.log(`✅ Validify Sentinel online as ${client.user.tag}`);
});

// ----------------------------------------------------
// 1) BOT ADDED ALERTS (guildMemberAdd + audit logs)
// ----------------------------------------------------
client.on("guildMemberAdd", async member => {
  if (!config.ENABLE_BOT_ADD_ALERTS) return;
  if (!member.user.bot) return; // only bots

  try {
    const guild = member.guild;
    const channel = getAlertChannel(guild);
    if (!channel) return;

    // Attempt to fetch who added the bot
    const logs = await guild.fetchAuditLogs({
      type: AuditLogEvent.BotAdd,
      limit: 1
    });

    const entry = logs.entries.first();
    const executor = entry?.executor;

    const description =
      `🤖 **A bot was added to the server**\n\n` +
      `**Bot:** ${member.user.tag} (${member.id})\n` +
      `**Added by:** ${executor ? `${executor.tag}` : "Unknown"}\n` +
      `**Action:** Review bot permissions & OAuth scopes.`;

    const embed = buildEmbed("Bot Added Alert", description, 0x00d4ff);

    await channel.send({ embeds: [embed] });

    logEvent({
      type: "BOT_ADDED",
      guildId: guild.id,
      botId: member.id,
      addedBy: executor?.id || null
    });
  } catch (e) {
    console.error("Bot add alert error:", e);
  }
});

// ----------------------------------------------------
// 2) ROLE CHANGE ALERTS (roleUpdate)
// ----------------------------------------------------
client.on("roleUpdate", async (oldRole, newRole) => {
  if (!config.ENABLE_ROLE_ALERTS) return;

  try {
    const guild = newRole.guild;
    const channel = getAlertChannel(guild);
    if (!channel) return;

    // Detect permission changes (simple compare)
    const oldPerms = oldRole.permissions.bitfield;
    const newPerms = newRole.permissions.bitfield;

    const nameChanged = oldRole.name !== newRole.name;
    const permsChanged = oldPerms !== newPerms;

    if (!nameChanged && !permsChanged) return;

    // Try to find executor via audit log
    const logs = await guild.fetchAuditLogs({
      type: AuditLogEvent.RoleUpdate,
      limit: 1
    });

    const entry = logs.entries.first();
    const executor = entry?.executor;

    let details = `🛡️ **Role updated**\n\n**Role:** ${newRole.name}\n`;

    if (nameChanged) {
      details += `**Name change:** "${oldRole.name}" → "${newRole.name}"\n`;
    }
    if (permsChanged) {
      details += `**Permissions changed:** Yes\n`;
      details += `**Action:** Review this role’s privileges.\n`;
    }

    details += `\n**Changed by:** ${executor ? executor.tag : "Unknown"}`;

    const embed = buildEmbed("Role Change Alert", details, 0x00ff88);

    await channel.send({ embeds: [embed] });

    logEvent({
      type: "ROLE_UPDATED",
      guildId: guild.id,
      roleId: newRole.id,
      changedBy: executor?.id || null,
      nameChanged,
      permsChanged
    });
  } catch (e) {
    console.error("Role update alert error:", e);
  }
});

// ----------------------------------------------------
// 3) WEBHOOK CREATED ALERTS
// ----------------------------------------------------
client.on("webhooksUpdate", async channelUpdated => {
  if (!config.ENABLE_WEBHOOK_ALERTS) return;

  try {
    const guild = channelUpdated.guild;
    const alertChannel = getAlertChannel(guild);
    if (!alertChannel) return;

    // Fetch recent audit logs for webhooks
    const logs = await guild.fetchAuditLogs({
      type: AuditLogEvent.WebhookCreate,
      limit: 1
    });

    const entry = logs.entries.first();
    if (!entry) return;

    const executor = entry.executor;
    const target = entry.target; // webhook object (may be partial)
    const createdIn = channelUpdated;

    const description =
      `🪝 **Webhook created**\n\n` +
      `**Channel:** ${createdIn?.name || "Unknown"}\n` +
      `**Created by:** ${executor ? executor.tag : "Unknown"}\n` +
      `**Webhook:** ${target?.name || "Unknown"}\n\n` +
      `**Action:** Verify this webhook is authorized.`;

    const embed = buildEmbed("Webhook Alert", description, 0xffaa00);

    await alertChannel.send({ embeds: [embed] });

    logEvent({
      type: "WEBHOOK_CREATED",
      guildId: guild.id,
      channelId: createdIn?.id || null,
      createdBy: executor?.id || null,
      webhookName: target?.name || null
    });
  } catch (e) {
    // webhooksUpdate fires for many reasons; be tolerant
    // لا
    // We only warn if we can confirm via audit logs
  }
});

// ----------------------------------------------------
// 4) SUSPICIOUS LINK ALERTS (messageCreate)
// ----------------------------------------------------
client.on("messageCreate", async message => {
  if (!config.ENABLE_LINK_ALERTS) return;
  if (!message.guild) return;
  if (message.author.bot) return;

  try {
    const urls = extractUrls(message.content);
    const keywordFlag = containsSuspiciousKeyword(message.content);

    if (!urls.length && !keywordFlag) return;

    let suspiciousHits = [];

    for (const url of urls) {
      const domain = getDomain(url);
      if (!domain) continue;

      // Allowlist overrides other checks
      if (isAllowlisted(domain)) continue;

      if (isSuspiciousDomain(domain)) {
        suspiciousHits.push({ url, reason: "Known shortener or risky domain pattern" });
      }
    }

    // If no URL-based hits but keywords are suspicious,
    // we still produce a low-severity alert.
    const shouldAlert = suspiciousHits.length > 0 || keywordFlag;

    if (!shouldAlert) return;

    const alertChannel = getAlertChannel(message.guild);
    if (!alertChannel) return;

    const hitText = suspiciousHits.length
      ? suspiciousHits.map(h => `• ${h.url}\n  ↳ ${h.reason}`).join("\n")
      : "• No URL match. Keyword-only flag.";

    const description =
      `🔗 **Potential phishing / scam pattern detected**\n\n` +
      `**User:** ${message.author.tag}\n` +
      `**Channel:** ${message.channel?.name || "Unknown"}\n\n` +
      `**Reason(s):**\n${hitText}\n\n` +
      `**Keyword flag:** ${keywordFlag ? "Yes" : "No"}\n` +
      `**Action:** Review message and verify against your official links.`;

    const embed = buildEmbed("Suspicious Link Alert", description, 0xff4444);

    await alertChannel.send({ embeds: [embed] });

    logEvent({
      type: "SUSPICIOUS_LINK",
      guildId: message.guild.id,
      channelId: message.channel.id,
      userId: message.author.id,
      keywordFlag,
      urls
    });
  } catch (e) {
    console.error("Link alert error:", e);
  }
});

// --- Login ---
client.login(process.env.DISCORD_BOT_TOKEN);

